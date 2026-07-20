| node   | outcome                        | fields                                              | expect      |
|--------|--------------------------------|-----------------------------------------------------|-------------|
| assess | db backups failing, data risk  | data_at_risk=true; user_facing=false; error_rate=0  | sev1_page   |
| assess | checkout 30% erroring          | user_facing=true; error_rate=30; data_at_risk=false | sev1_page   |
| assess | login slow, 8% errors          | user_facing=true; error_rate=8; data_at_risk=false  | sev2_oncall |
| assess | internal job 2% errors         | user_facing=false; error_rate=2; data_at_risk=false | sev3_ticket |
| assess | single transient blip          | user_facing=false; error_rate=0; data_at_risk=false | watch       |
