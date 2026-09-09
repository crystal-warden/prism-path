@id("group:eng#member|viewer|folder:f1")
permit(principal in Group::"eng", action == Action::"view", resource in Folder::"f1");

@id("user:bob|viewer|doc:d2")
permit(principal == User::"bob", action == Action::"view", resource in Doc::"d2");

@id("user:dana|viewer|folder:f2")
permit(principal == User::"dana", action == Action::"view", resource in Folder::"f2");
