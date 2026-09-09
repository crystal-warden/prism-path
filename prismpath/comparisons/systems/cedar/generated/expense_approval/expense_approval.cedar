@id("r1")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    (context has vendor_risk && context.vendor_risk == "high")
};

@id("r2")
@outcome("abstain")
permit(principal, action == Action::"decide", resource)
when {
    (!(context has receipt_present) || (context has receipt_present && context.receipt_present == false)) &&
    !(context has vendor_risk && context.vendor_risk == "high")
};

@id("r3")
@outcome("escalate_human")
permit(principal, action == Action::"decide", resource)
when {
    (context has amount_cents && context.amount_cents > 1000000) &&
    !(context has vendor_risk && context.vendor_risk == "high") &&
    !(!(context has receipt_present) || (context has receipt_present && context.receipt_present == false))
};

@id("r4")
@outcome("escalate_human")
permit(principal, action == Action::"decide", resource)
when {
    ((context has category && context.category == "other") && (context has amount_cents && context.amount_cents > 50000)) &&
    !(context has vendor_risk && context.vendor_risk == "high") &&
    !(!(context has receipt_present) || (context has receipt_present && context.receipt_present == false)) &&
    !(context has amount_cents && context.amount_cents > 1000000)
};

@id("r5")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    (context has amount_cents && context.amount_cents <= 50000) &&
    !(context has vendor_risk && context.vendor_risk == "high") &&
    !(!(context has receipt_present) || (context has receipt_present && context.receipt_present == false)) &&
    !(context has amount_cents && context.amount_cents > 1000000) &&
    !((context has category && context.category == "other") && (context has amount_cents && context.amount_cents > 50000))
};

@id("r6")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    ((context has requester_role && ["manager", "director"].contains(context.requester_role)) && (context has amount_cents && context.amount_cents <= 1000000)) &&
    !(context has vendor_risk && context.vendor_risk == "high") &&
    !(!(context has receipt_present) || (context has receipt_present && context.receipt_present == false)) &&
    !(context has amount_cents && context.amount_cents > 1000000) &&
    !((context has category && context.category == "other") && (context has amount_cents && context.amount_cents > 50000)) &&
    !(context has amount_cents && context.amount_cents <= 50000)
};

@id("r7")
@outcome("escalate_human")
permit(principal, action == Action::"decide", resource)
when {
    true &&
    !(context has vendor_risk && context.vendor_risk == "high") &&
    !(!(context has receipt_present) || (context has receipt_present && context.receipt_present == false)) &&
    !(context has amount_cents && context.amount_cents > 1000000) &&
    !((context has category && context.category == "other") && (context has amount_cents && context.amount_cents > 50000)) &&
    !(context has amount_cents && context.amount_cents <= 50000) &&
    !((context has requester_role && ["manager", "director"].contains(context.requester_role)) && (context has amount_cents && context.amount_cents <= 1000000))
};
