@id("r1")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    (context has dst_port && context.dst_port == 23)
};

@id("r2")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    ((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true)) &&
    !(context has dst_port && context.dst_port == 23)
};

@id("r3")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    (context has dst_port && context.dst_port == 22) &&
    !(context has dst_port && context.dst_port == 23) &&
    !((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true))
};

@id("r4")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    ((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len <= 512)) &&
    !(context has dst_port && context.dst_port == 23) &&
    !((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true)) &&
    !(context has dst_port && context.dst_port == 22)
};

@id("r5")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    ((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len > 512)) &&
    !(context has dst_port && context.dst_port == 23) &&
    !((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true)) &&
    !(context has dst_port && context.dst_port == 22) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len <= 512))
};

@id("r6")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    (context has dst_port && context.dst_port == 443) &&
    !(context has dst_port && context.dst_port == 23) &&
    !((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true)) &&
    !(context has dst_port && context.dst_port == 22) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len <= 512)) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len > 512))
};

@id("r7")
@outcome("observe")
permit(principal, action == Action::"decide", resource)
when {
    (context has pkt_len && context.pkt_len >= 1400) &&
    !(context has dst_port && context.dst_port == 23) &&
    !((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true)) &&
    !(context has dst_port && context.dst_port == 22) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len <= 512)) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len > 512)) &&
    !(context has dst_port && context.dst_port == 443)
};

@id("r8")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    (context has protocol && context.protocol == 1) &&
    !(context has dst_port && context.dst_port == 23) &&
    !((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true)) &&
    !(context has dst_port && context.dst_port == 22) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len <= 512)) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len > 512)) &&
    !(context has dst_port && context.dst_port == 443) &&
    !(context has pkt_len && context.pkt_len >= 1400)
};

@id("r9")
@outcome("observe")
permit(principal, action == Action::"decide", resource)
when {
    true &&
    !(context has dst_port && context.dst_port == 23) &&
    !((context has dst_port && context.dst_port == 22) && (context has src_internal && context.src_internal == true)) &&
    !(context has dst_port && context.dst_port == 22) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len <= 512)) &&
    !((context has dst_port && context.dst_port == 53) && (context has pkt_len && context.pkt_len > 512)) &&
    !(context has dst_port && context.dst_port == 443) &&
    !(context has pkt_len && context.pkt_len >= 1400) &&
    !(context has protocol && context.protocol == 1)
};
