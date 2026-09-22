resource "google_storage_bucket" "agent_artifacts" {
  name          = "${var.gcp_project_id}-artifacts"
  location      = var.gcp_region
  force_destroy = true
}

resource "google_bigquery_dataset" "telemetry" {
  dataset_id = "agent_telemetry"
  location   = "US"
}

resource "google_compute_instance" "worker_vm" {
  name         = "agent-worker-vm"
  machine_type = "e2-medium"
  zone         = var.gcp_zone
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
  }
}
