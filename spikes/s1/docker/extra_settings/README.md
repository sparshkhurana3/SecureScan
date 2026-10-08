Intentionally empty. DefectDojo's compose file bind-mounts this directory at /app/docker/extra_settings.
A local_settings.py placed here would be copied to dojo/settings/ on start (see the upstream README of the same directory).
The directory must exist before `docker compose up`, otherwise Docker creates it owned by root.
