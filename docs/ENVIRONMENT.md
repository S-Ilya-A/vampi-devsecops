# Environment notes

These are notes, not a script. Turning them into something reproducible is Task 1.

## Host

- One laptop: 16 GB RAM, 8 cores, Docker, plus one VM (Vagrant or Multipass).
- Everything must work offline once the images are pulled. Pin image tags so a later run never needs a pull.

## GitLab CE

- Image `gitlab/gitlab-ce` (pin a 17.x tag). The first boot takes 3-5 minutes. Watch `/-/readiness`.
- Out of the box it wants about 4 GB of RAM. Settings worth putting in `GITLAB_OMNIBUS_CONFIG` on a laptop:
  `puma['worker_processes'] = 0`, `sidekiq['concurrency'] = 5`, `prometheus_monitoring['enable'] = false`.
- `external_url` must be a name that the browser on the host, the runner container and job containers can all resolve. `localhost` works for the browser only.
- The pipeline pushes images to `$CI_REGISTRY_IMAGE`, so the **container registry must be enabled** (`registry_external_url`). Plain HTTP is fine on a laptop, but every Docker daemon that pulls from it (dind in jobs, the staging VM) must list it under `insecure-registries`.
- The initial root password is in `/etc/gitlab/initial_root_password` inside the container. It is deleted after 24 hours.

## GitLab runner

- Image `gitlab/gitlab-runner` (pin it). Use the Docker executor.
- Since GitLab 16, runners are created in the UI or via the API (`POST /api/v4/user/runners`), which returns a `glrt-` token. Registration tokens are deprecated.
- The build jobs use Docker-in-Docker, so the runner needs `privileged = true`.
- Job containers start on the runner's Docker network. `network_mode` and `clone_url` in `config.toml` decide whether they can reach GitLab and the registry.

## Application

- `docker compose up --build` starts Postgres, the API on `:5000` and the web client on `:8088`.
- The database is empty until `GET /createdb` is called.
- `vulnerable=1` turns VAmPI's vulnerable code paths on. Leave it on: the pen-test findings refer to that mode.
