resource "google_service_account" "llm_runner" {
  account_id   = "llm-runner-sa"
  display_name = "LLM Runner SA"
}

resource "google_project_iam_member" "llm_runner_ai" {
  project = var.gcp_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.llm_runner.email}"
}

resource "google_service_account_key" "exported_key" {
  service_account_id = google_service_account.llm_runner.name
}
