@id("r1")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    (context has user_role && context.user_role == "admin")
};

@id("r2")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    ((context has resource_sensitivity && context.resource_sensitivity == "high") && (context has user_role && !(["admin", "manager"].contains(context.user_role)))) &&
    !(context has user_role && context.user_role == "admin")
};

@id("r3")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    (context has user_id && context has resource_owner_id && context.user_id == context.resource_owner_id) &&
    !(context has user_role && context.user_role == "admin") &&
    !((context has resource_sensitivity && context.resource_sensitivity == "high") && (context has user_role && !(["admin", "manager"].contains(context.user_role))))
};

@id("r4")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    ((context has action && context.action == "read") && (context has user_groups && context has resource_groups && context.user_groups.containsAny(context.resource_groups))) &&
    !(context has user_role && context.user_role == "admin") &&
    !((context has resource_sensitivity && context.resource_sensitivity == "high") && (context has user_role && !(["admin", "manager"].contains(context.user_role)))) &&
    !(context has user_id && context has resource_owner_id && context.user_id == context.resource_owner_id)
};

@id("r5")
@outcome("allow")
permit(principal, action == Action::"decide", resource)
when {
    (principal in Role::"manager" && (context has action && ["read", "write"].contains(context.action)) && (context has hour_utc && context.hour_utc >= 8) && (context has hour_utc && context.hour_utc < 18)) &&
    !(context has user_role && context.user_role == "admin") &&
    !((context has resource_sensitivity && context.resource_sensitivity == "high") && (context has user_role && !(["admin", "manager"].contains(context.user_role)))) &&
    !(context has user_id && context has resource_owner_id && context.user_id == context.resource_owner_id) &&
    !((context has action && context.action == "read") && (context has user_groups && context has resource_groups && context.user_groups.containsAny(context.resource_groups)))
};

@id("r6")
@outcome("deny")
permit(principal, action == Action::"decide", resource)
when {
    true &&
    !(context has user_role && context.user_role == "admin") &&
    !((context has resource_sensitivity && context.resource_sensitivity == "high") && (context has user_role && !(["admin", "manager"].contains(context.user_role)))) &&
    !(context has user_id && context has resource_owner_id && context.user_id == context.resource_owner_id) &&
    !((context has action && context.action == "read") && (context has user_groups && context has resource_groups && context.user_groups.containsAny(context.resource_groups))) &&
    !(principal in Role::"manager" && (context has action && ["read", "write"].contains(context.action)) && (context has hour_utc && context.hour_utc >= 8) && (context has hour_utc && context.hour_utc < 18))
};
