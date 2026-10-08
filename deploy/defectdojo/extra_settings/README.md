# DefectDojo extra settings

Mounted read-only at `/app/docker/extra_settings` in DefectDojo's `uwsgi`, `celerybeat`, `celeryworker` and
`initializer` containers. At start-up DefectDojo copies the files in this directory into its `dojo/settings/`
package; a `local_settings.py` here is read after DefectDojo's own settings.

Empty on purpose: every setting SecureScan changes is an environment variable in `../override.yaml`. Put a
`local_settings.py` here only when a setting has no `DD_*` variable (record why in `docs/decisions.md`).
This README is copied along with the rest and is harmless.
