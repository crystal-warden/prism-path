//! Facet Vector sink with bounded buffering and DIL lossy link simulation.
//!
//! Reads Vector shaped events as NDJSON from standard input or a TCP socket, derives
//! the Facet codebook from a signed PrismPath policy, and encodes each event decision
//! fields to the Facet wire via prismpath_telemetry_rs. Batches of readings are sealed
//! into the EpochStore and emitted immediately as single line JSON batch reports on stdout.
//! When the downstream consumer queue is full, the sink drops the oldest queued batch and
//! records a provable gap in the EpochStore under the drop-oldest, gap recorded backpressure policy.

use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::epochs::EpochStore;
use prismpath_telemetry_rs::quantizer::{self, FieldPartition};
use prismpath_telemetry_rs::selfheal::{Receiver, Sender};
use prismpath_telemetry_rs::wire;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::net::TcpListener;
use std::sync::mpsc::{sync_channel, Receiver as MpscReceiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The options one run is given on the command line.
#[derive(Clone, Debug)]
struct RunOptions {
    batch_size: usize,
    max_queued_batches: usize,
    consumer_delay_milliseconds: u64,
    interference_rate: Option<f64>,
    used_seed: u64,
}

/// A JSON scalar as the kernel's value type; a null, list or object is not a reading value and yields None.
fn json_to_v(json_value: &serde_json::Value) -> Option<V> {
    match json_value {
        serde_json::Value::Bool(flag) => Some(V::Bool(*flag)),
        serde_json::Value::Number(number) => number.as_f64().map(V::Num),
        serde_json::Value::String(text) => Some(V::Str(text.clone())),
        _ => None,
    }
}

/// One step of the xorshift64 generator as a float in [0, 1). A tiny generator with an explicit
/// state is what makes a run reproducible from --seed; a library generator seeded from the clock is not.
fn next_f64(state: &mut u64) -> f64 {
    let mut scrambled = *state;
    scrambled ^= scrambled << 13;
    scrambled ^= scrambled >> 7;
    scrambled ^= scrambled << 17;
    *state = scrambled;
    (scrambled >> 11) as f64 / ((1u64 << 53) as f64)
}

/// The ratio a reader can trust: accepted input bytes over encoded payload bytes. Refused lines
/// stay out of the numerator, so they cannot inflate it; no payload means no ratio, never a division by zero.
fn calculate_ratio(accepted_bytes: usize, payload_bytes: usize) -> Option<f64> {
    if payload_bytes == 0 {
        None
    } else {
        Some(accepted_bytes as f64 / payload_bytes as f64)
    }
}

/// What waits in the bounded queue for the simulated consumer: the epoch a batch was sealed into.
struct QueuedBatch {
    epoch_id: usize,
}

/// One batch's accounting, kept separate per counter so a report can show what was accepted, what
/// was refused and what went on the wire without mixing them.
#[derive(Default)]
struct BatchAccumulator {
    batch_index: usize,
    readings_encoded: usize,
    lines_refused_unparseable: usize,
    lines_refused_unencodable: usize,
    accepted_input_bytes: usize,
    refused_input_bytes: usize,
    wire_bits: String,
}

/// The same counters summed over the run, for the summary.
#[derive(Default)]
struct SummaryTotals {
    readings_encoded: usize,
    lines_refused_unparseable: usize,
    lines_refused_unencodable: usize,
    accepted_input_bytes: usize,
    refused_input_bytes: usize,
    encoded_payload_bytes: usize,
    transport_overhead_bytes: usize,
}

/// Everything a batch flush needs, gathered so the flush and the input loop share one state.
struct BatchContext<'a> {
    epoch_store: &'a mut EpochStore,
    block_bits: usize,
    interference_rate: Option<f64>,
    random_state: &'a mut u64,
    sender_channel: &'a SyncSender<QueuedBatch>,
    receiver_arc: &'a Arc<Mutex<MpscReceiver<QueuedBatch>>>,
    batches_dropped_backpressure: &'a mut usize,
    summary_totals: &'a mut SummaryTotals,
}

/// Usage on stderr and exit 2, so stdout stays JSON lines only.
fn print_usage_and_exit() -> ! {
    eprintln!("usage: facet-vector-sink <flow.md> [--listen ADDR] [--interference P] [--batch N] [--max-queued Q] [--consumer-delay-ms D] [--seed S]");
    std::process::exit(2);
}

/// The batch over a lossy link: blocks dropped or corrupted at the interference rate, repaired by
/// the self heal proofs. Returns the transport overhead those proofs cost in bytes, which is the
/// price of recovery and is reported apart from the payload.
fn simulate_interference(
    batch_bits: &str,
    block_bits: usize,
    interference_rate: f64,
    random_state: &mut u64,
) -> usize {
    let sender = match Sender::new(batch_bits, block_bits) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let block_count = sender.n_blocks();
    let mut receiver = Receiver::new(sender.root.clone(), block_count);
    let mut transport_overhead_bytes = 32usize;
    let mut rounds = 0usize;

    loop {
        let targets = if rounds == 0 {
            (0..block_count).collect()
        } else {
            receiver.missing()
        };
        if targets.is_empty() {
            break;
        }
        for index in targets {
            let (block, proof) = sender.serve(index);
            transport_overhead_bytes += proof.len() * 64;
            if next_f64(random_state) < interference_rate {
                if next_f64(random_state) < 0.5 {
                    // Dropout: lost block.
                } else {
                    let mut block_bytes = block.into_bytes();
                    if !block_bytes.is_empty() {
                        let bit_index = (next_f64(random_state) * block_bytes.len() as f64) as usize % block_bytes.len();
                        block_bytes[bit_index] = if block_bytes[bit_index] == b'0' { b'1' } else { b'0' };
                    }
                    if let Ok(corrupted_block) = String::from_utf8(block_bytes) {
                        let _ = receiver.accept(index, &corrupted_block, &proof);
                    }
                }
            } else {
                let _ = receiver.accept(index, &block, &proof);
            }
        }
        rounds += 1;
        if rounds > 80 {
            break;
        }
    }
    transport_overhead_bytes
}

/// Hand a batch to the consumer without ever blocking input. When the queue is full the oldest
/// batch is dropped and its epoch marked as a gap: on a live feed the newest decision matters more
/// than the oldest, and a recorded gap is honest where a stalled feed would be silent.
fn enqueue_batch(
    sender_channel: &SyncSender<QueuedBatch>,
    receiver_arc: &Arc<Mutex<MpscReceiver<QueuedBatch>>>,
    epoch_store: &mut EpochStore,
    epoch_id: usize,
    batches_dropped_backpressure: &mut usize,
) {
    let queued = QueuedBatch { epoch_id };
    match sender_channel.try_send(queued) {
        Ok(()) => {}
        Err(TrySendError::Full(batch_to_send)) => {
            let guard = receiver_arc.lock().expect("lock receiver mutex");
            if let Ok(oldest_batch) = guard.try_recv() {
                if let Some(epoch) = epoch_store.epochs.get_mut(oldest_batch.epoch_id) {
                    epoch.dropped_under_pressure = true;
                }
                *batches_dropped_backpressure += 1;
            }
            drop(guard);
            let _ = sender_channel.try_send(batch_to_send);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}

/// Seal the batch as an epoch, report it at once so a long lived connection shows results before
/// it closes, then queue it for the consumer.
fn flush_batch(batch: &mut BatchAccumulator, context: &mut BatchContext<'_>) {
    let epoch = context.epoch_store.seal(&batch.wire_bits);
    let encoded_payload_bytes = batch.wire_bits.len().div_ceil(8);

    let transport_overhead_bytes = if let Some(rate) = context.interference_rate {
        simulate_interference(&batch.wire_bits, context.block_bits, rate, context.random_state)
    } else {
        0
    };

    let compression_ratio = calculate_ratio(batch.accepted_input_bytes, encoded_payload_bytes);

    let report = serde_json::json!({
        "batch_index": batch.batch_index,
        "epoch_id": epoch.id,
        "chained_root": epoch.chained_root,
        "merkle_root": epoch.merkle_root,
        "readings_encoded": batch.readings_encoded,
        "lines_refused_unparseable": batch.lines_refused_unparseable,
        "lines_refused_unencodable": batch.lines_refused_unencodable,
        "accepted_input_bytes": batch.accepted_input_bytes,
        "refused_input_bytes": batch.refused_input_bytes,
        "encoded_payload_bytes": encoded_payload_bytes,
        "transport_overhead_bytes": transport_overhead_bytes,
        "compression_ratio": compression_ratio,
    });

    println!("{}", serde_json::to_string(&report).expect("serialize batch report"));

    enqueue_batch(
        context.sender_channel,
        context.receiver_arc,
        context.epoch_store,
        epoch.id,
        context.batches_dropped_backpressure,
    );

    context.summary_totals.readings_encoded += batch.readings_encoded;
    context.summary_totals.lines_refused_unparseable += batch.lines_refused_unparseable;
    context.summary_totals.lines_refused_unencodable += batch.lines_refused_unencodable;
    context.summary_totals.accepted_input_bytes += batch.accepted_input_bytes;
    context.summary_totals.refused_input_bytes += batch.refused_input_bytes;
    context.summary_totals.encoded_payload_bytes += encoded_payload_bytes;
    context.summary_totals.transport_overhead_bytes += transport_overhead_bytes;
}

/// The simulated consumer: a thread that takes --consumer-delay-ms per batch, the slow reader the
/// backpressure policy exists for.
fn spawn_consumer_thread(
    max_queued_batches: usize,
    consumer_delay_milliseconds: u64,
) -> (
    SyncSender<QueuedBatch>,
    Arc<Mutex<MpscReceiver<QueuedBatch>>>,
    std::thread::JoinHandle<()>,
) {
    let (sender, receiver) = sync_channel::<QueuedBatch>(max_queued_batches);
    let receiver_arc = Arc::new(Mutex::new(receiver));
    let receiver_clone = Arc::clone(&receiver_arc);

    let handle = std::thread::spawn(move || {
        loop {
            let batch = {
                let guard = receiver_clone.lock().expect("lock receiver mutex");
                guard.recv()
            };
            let Ok(_batch) = batch else {
                break;
            };
            if consumer_delay_milliseconds > 0 {
                std::thread::sleep(std::time::Duration::from_millis(consumer_delay_milliseconds));
            }
        }
    });

    (sender, receiver_arc, handle)
}

/// The input loop: one line is one event; a line that does not parse or does not encode is refused
/// and its bytes counted as refused, never as accepted.
fn process_input<R: BufRead>(
    reader: R,
    partitions: &HashMap<String, FieldPartition>,
    field_names: &[String],
    options: RunOptions,
) {
    let block_bits = (64 * field_names.len()).max(64);
    let mut epoch_store = EpochStore::new(block_bits, 10000);
    let mut random_state = if options.used_seed == 0 { 1 } else { options.used_seed };

    let (sender_channel, receiver_arc, consumer_handle) =
        spawn_consumer_thread(options.max_queued_batches, options.consumer_delay_milliseconds);

    let mut summary_totals = SummaryTotals::default();
    let mut batches_dropped_backpressure = 0usize;

    let mut batch_counter = 0usize;
    let mut current_batch = BatchAccumulator {
        batch_index: batch_counter,
        ..Default::default()
    };

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(text) => text,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let line_byte_count = line.len();

        let event_value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(parsed) => parsed,
            Err(_) => {
                current_batch.lines_refused_unparseable += 1;
                current_batch.refused_input_bytes += line_byte_count;
                continue;
            }
        };

        let mut reading: HashMap<String, V> = HashMap::new();
        for field in field_names {
            if let Some(val) = event_value.get(field).and_then(json_to_v) {
                reading.insert(field.clone(), val);
            }
        }

        match wire::encode_reading(partitions, &reading) {
            Ok(bits) => {
                current_batch.wire_bits.push_str(&bits);
                current_batch.readings_encoded += 1;
                current_batch.accepted_input_bytes += line_byte_count;
            }
            Err(_) => {
                current_batch.lines_refused_unencodable += 1;
                current_batch.refused_input_bytes += line_byte_count;
            }
        }

        if current_batch.readings_encoded >= options.batch_size {
            let mut context = BatchContext {
                epoch_store: &mut epoch_store,
                block_bits,
                interference_rate: options.interference_rate,
                random_state: &mut random_state,
                sender_channel: &sender_channel,
                receiver_arc: &receiver_arc,
                batches_dropped_backpressure: &mut batches_dropped_backpressure,
                summary_totals: &mut summary_totals,
            };
            flush_batch(&mut current_batch, &mut context);
            batch_counter += 1;
            current_batch = BatchAccumulator {
                batch_index: batch_counter,
                ..Default::default()
            };
        }
    }

    if current_batch.readings_encoded > 0
        || current_batch.lines_refused_unparseable > 0
        || current_batch.lines_refused_unencodable > 0
    {
        let mut context = BatchContext {
            epoch_store: &mut epoch_store,
            block_bits,
            interference_rate: options.interference_rate,
            random_state: &mut random_state,
            sender_channel: &sender_channel,
            receiver_arc: &receiver_arc,
            batches_dropped_backpressure: &mut batches_dropped_backpressure,
            summary_totals: &mut summary_totals,
        };
        flush_batch(&mut current_batch, &mut context);
    }

    drop(sender_channel);
    let _ = consumer_handle.join();

    if let Some(rate) = options.interference_rate {
        eprintln!(
            "[facet-sink] DIL self-heal over a lossy link (interference p={})",
            rate
        );
    }

    let summary_ratio = calculate_ratio(
        summary_totals.accepted_input_bytes,
        summary_totals.encoded_payload_bytes,
    );

    let summary_report = serde_json::json!({
        "readings_encoded": summary_totals.readings_encoded,
        "lines_refused_unparseable": summary_totals.lines_refused_unparseable,
        "lines_refused_unencodable": summary_totals.lines_refused_unencodable,
        "accepted_input_bytes": summary_totals.accepted_input_bytes,
        "refused_input_bytes": summary_totals.refused_input_bytes,
        "encoded_payload_bytes": summary_totals.encoded_payload_bytes,
        "transport_overhead_bytes": summary_totals.transport_overhead_bytes,
        "compression_ratio": summary_ratio,
        "batches_dropped_backpressure": batches_dropped_backpressure,
        "backpressure_policy": "drop-oldest, gap recorded",
        "epoch_chain_length": epoch_store.chain().len(),
        "gaps": epoch_store.gaps(),
        "verify_chain": epoch_store.verify_chain(),
        "seed": options.used_seed,
    });

    println!("{}", serde_json::to_string(&summary_report).expect("serialize summary report"));
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mut flow_file_path: Option<String> = None;
    let mut listen_address: Option<String> = None;
    let mut interference_rate: Option<f64> = None;
    let mut batch_size: usize = 256;
    let mut max_queued_batches: usize = 8;
    let mut consumer_delay_milliseconds: u64 = 0;
    let mut seed_value: Option<u64> = None;

    let mut argument_index = 1;
    while argument_index < arguments.len() {
        match arguments[argument_index].as_str() {
            "--listen" => {
                let Some(val) = arguments.get(argument_index + 1) else {
                    print_usage_and_exit();
                };
                listen_address = Some(val.clone());
                argument_index += 2;
            }
            "--interference" => {
                let Some(val) = arguments.get(argument_index + 1) else {
                    print_usage_and_exit();
                };
                let Ok(parsed) = val.parse::<f64>() else {
                    print_usage_and_exit();
                };
                interference_rate = Some(parsed);
                argument_index += 2;
            }
            "--batch" => {
                let Some(val) = arguments.get(argument_index + 1) else {
                    print_usage_and_exit();
                };
                let Ok(parsed) = val.parse::<usize>() else {
                    print_usage_and_exit();
                };
                if parsed == 0 {
                    print_usage_and_exit();
                }
                batch_size = parsed;
                argument_index += 2;
            }
            "--max-queued" => {
                let Some(val) = arguments.get(argument_index + 1) else {
                    print_usage_and_exit();
                };
                let Ok(parsed) = val.parse::<usize>() else {
                    print_usage_and_exit();
                };
                if parsed == 0 {
                    print_usage_and_exit();
                }
                max_queued_batches = parsed;
                argument_index += 2;
            }
            "--consumer-delay-ms" => {
                let Some(val) = arguments.get(argument_index + 1) else {
                    print_usage_and_exit();
                };
                let Ok(parsed) = val.parse::<u64>() else {
                    print_usage_and_exit();
                };
                consumer_delay_milliseconds = parsed;
                argument_index += 2;
            }
            "--seed" => {
                let Some(val) = arguments.get(argument_index + 1) else {
                    print_usage_and_exit();
                };
                let Ok(parsed) = val.parse::<u64>() else {
                    print_usage_and_exit();
                };
                seed_value = Some(parsed);
                argument_index += 2;
            }
            flag if flag.starts_with('-') => {
                print_usage_and_exit();
            }
            argument => {
                if flow_file_path.is_none() {
                    flow_file_path = Some(argument.to_string());
                } else {
                    print_usage_and_exit();
                }
                argument_index += 1;
            }
        }
    }

    let flow_file_path = flow_file_path.unwrap_or_else(|| {
        print_usage_and_exit();
    });

    let used_seed = seed_value.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos() as u64
            | 1
    });

    let options = RunOptions {
        batch_size,
        max_queued_batches,
        consumer_delay_milliseconds,
        interference_rate,
        used_seed,
    };

    let flow_text = std::fs::read_to_string(&flow_file_path).expect("read flow file");
    let graph = parse(&flow_text);
    let partitions = quantizer::build_partitions(&graph);
    let field_names = wire::order(&partitions);
    eprintln!(
        "[facet-sink] codebook from policy: {} field(s): {:?}",
        field_names.len(),
        field_names
    );

    if let Some(address) = listen_address {
        let listener = TcpListener::bind(&address).expect("bind socket");
        eprintln!("[facet-sink] listening on {}...", address);
        let (stream, _peer) = listener.accept().expect("accept socket connection");
        process_input(
            BufReader::new(stream),
            &partitions,
            &field_names,
            options,
        );
    } else {
        process_input(
            io::stdin().lock(),
            &partitions,
            &field_names,
            options,
        );
    }
}
