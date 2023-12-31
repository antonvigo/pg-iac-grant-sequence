output "grants_to_group" {
  description = "List of granted privileges for specified role"
  value = {
    name       = var.group_role
    privileges = local.privileges
    schema     = local.schema
    sequences  = local.sequences
  }
}

output "sql_script" {
  description = "Applied SQL script"
  value       = local.sql_script
}
