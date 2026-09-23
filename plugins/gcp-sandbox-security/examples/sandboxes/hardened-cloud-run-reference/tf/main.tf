resource "google_storage_bucket" "app_bucket" {
  name          = "${var.gcp_project_id}-bucket"
  location      = "US"
  force_destroy = true
}
