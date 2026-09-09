@id("r1")
@outcome("escalate_human")
permit(principal, action == Action::"decide", resource)
when {
    (context has human_requested && context.human_requested == true)
};

@id("r2")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    ((context has data_class && context.data_class == "cui") && (context has target_scope && context.target_scope == "external")) &&
    !(context has human_requested && context.human_requested == true)
};

@id("r3")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    ((context has action_class && context.action_class == "delete") && (context has reversible && context.reversible == false) && (context has target_scope && ["org", "external"].contains(context.target_scope))) &&
    !(context has human_requested && context.human_requested == true) &&
    !((context has data_class && context.data_class == "cui") && (context has target_scope && context.target_scope == "external"))
};

@id("r4")
@outcome("escalate_human")
permit(principal, action == Action::"decide", resource)
when {
    ((context has action_class && ["send_external", "execute"].contains(context.action_class)) && (context has data_class && ["confidential", "cui"].contains(context.data_class))) &&
    !(context has human_requested && context.human_requested == true) &&
    !((context has data_class && context.data_class == "cui") && (context has target_scope && context.target_scope == "external")) &&
    !((context has action_class && context.action_class == "delete") && (context has reversible && context.reversible == false) && (context has target_scope && ["org", "external"].contains(context.target_scope)))
};

@id("r5")
@outcome("abstain")
permit(principal, action == Action::"decide", resource)
when {
    (context has worker_confidence && context.worker_confidence < 60) &&
    !(context has human_requested && context.human_requested == true) &&
    !((context has data_class && context.data_class == "cui") && (context has target_scope && context.target_scope == "external")) &&
    !((context has action_class && context.action_class == "delete") && (context has reversible && context.reversible == false) && (context has target_scope && ["org", "external"].contains(context.target_scope))) &&
    !((context has action_class && ["send_external", "execute"].contains(context.action_class)) && (context has data_class && ["confidential", "cui"].contains(context.data_class)))
};

@id("r6")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    (context has action_class && context.action_class == "read") &&
    !(context has human_requested && context.human_requested == true) &&
    !((context has data_class && context.data_class == "cui") && (context has target_scope && context.target_scope == "external")) &&
    !((context has action_class && context.action_class == "delete") && (context has reversible && context.reversible == false) && (context has target_scope && ["org", "external"].contains(context.target_scope))) &&
    !((context has action_class && ["send_external", "execute"].contains(context.action_class)) && (context has data_class && ["confidential", "cui"].contains(context.data_class))) &&
    !(context has worker_confidence && context.worker_confidence < 60)
};

@id("r7")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    ((context has reversible && context.reversible == true) && (context has target_scope && ["own", "team"].contains(context.target_scope))) &&
    !(context has human_requested && context.human_requested == true) &&
    !((context has data_class && context.data_class == "cui") && (context has target_scope && context.target_scope == "external")) &&
    !((context has action_class && context.action_class == "delete") && (context has reversible && context.reversible == false) && (context has target_scope && ["org", "external"].contains(context.target_scope))) &&
    !((context has action_class && ["send_external", "execute"].contains(context.action_class)) && (context has data_class && ["confidential", "cui"].contains(context.data_class))) &&
    !(context has worker_confidence && context.worker_confidence < 60) &&
    !(context has action_class && context.action_class == "read")
};

@id("r8")
@outcome("escalate_human")
permit(principal, action == Action::"decide", resource)
when {
    true &&
    !(context has human_requested && context.human_requested == true) &&
    !((context has data_class && context.data_class == "cui") && (context has target_scope && context.target_scope == "external")) &&
    !((context has action_class && context.action_class == "delete") && (context has reversible && context.reversible == false) && (context has target_scope && ["org", "external"].contains(context.target_scope))) &&
    !((context has action_class && ["send_external", "execute"].contains(context.action_class)) && (context has data_class && ["confidential", "cui"].contains(context.data_class))) &&
    !(context has worker_confidence && context.worker_confidence < 60) &&
    !(context has action_class && context.action_class == "read") &&
    !((context has reversible && context.reversible == true) && (context has target_scope && ["own", "team"].contains(context.target_scope)))
};
