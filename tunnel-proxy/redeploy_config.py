"""Copy saved Docker create settings for startup.sh's image-only update.

Uses only the standard library and a local Docker Unix socket. Configuration
containing secrets travels over stdin/stdout, never through temporary files or
command arguments. No container is changed by the prepare command.
"""

from __future__ import annotations

import copy
import http.client
import json
import os
import socket
import subprocess
import sys
from urllib.parse import quote, unquote, urlsplit


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=30)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def docker_json(*args):
    # Do not forward daemon output: it may include configuration/credentials.
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise RuntimeError("could not read Docker configuration")
    return json.loads(result.stdout)


def docker_socket():
    # DOCKER_CONTEXT overrides DOCKER_HOST, as it does in the Docker CLI.
    context = os.environ.get("DOCKER_CONTEXT")
    host = os.environ.get("DOCKER_HOST") if not context else None
    if not host:
        args = ["context", "inspect"]
        if context:
            args.append(context)
        host = docker_json(*args)[0]["Endpoints"]["docker"]["Host"]
    endpoint = urlsplit(host)
    if endpoint.scheme != "unix" or endpoint.netloc or not endpoint.path:
        raise RuntimeError("image-only update requires a local Unix-socket Docker daemon")
    return unquote(endpoint.path)


def request(path, method, endpoint, payload=None):
    conn = UnixConnection(path)
    try:
        body = None if payload is None else json.dumps(payload).encode()
        conn.request(method, endpoint, body=body, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read()
        if response.status >= 400:
            # Docker's error body can echo environment values. Keep it private.
            raise RuntimeError(f"Docker API {method} failed (HTTP {response.status})")
        return json.loads(data) if data else {}
    finally:
        conn.close()


def create_config(container, image_id):
    """Retain create-time settings, not runtime IDs or assigned IP addresses."""
    config = copy.deepcopy(container["Config"])
    config["Image"] = image_id
    # These are inspect-only fields, not container-create options.
    for key in ("HostnamePath", "HostsPath", "ResolvConfPath"):
        config.pop(key, None)
    host = copy.deepcopy(container["HostConfig"])
    if host.get("AutoRemove"):
        raise RuntimeError("cannot safely update an auto-remove container (rollback would be lost)")
    if container.get("State", {}).get("Paused"):
        raise RuntimeError("unpause the existing container before updating it")

    # A blank host port (or --publish-all) would allocate different public ports
    # on recreate. Pin any previously assigned ports to their effective values.
    actual_ports = container.get("NetworkSettings", {}).get("Ports") or {}
    bindings = host.get("PortBindings") or {}
    for port, actual in actual_ports.items():
        if actual and (host.get("PublishAllPorts") or any(
            not bind.get("HostPort") or bind["HostPort"] == "0"
            for bind in bindings.get(port) or []
        )):
            bindings[port] = copy.deepcopy(actual)
    if bindings:
        host["PortBindings"] = bindings
    if host.get("PublishAllPorts"):
        if not any(actual_ports.values()):
            raise RuntimeError("cannot preserve publish-all ports before the container has been started")
        host["PublishAllPorts"] = False

    # Image-declared anonymous volumes must be reused by name, otherwise create
    # allocates fresh volumes and the replacement silently loses its data.
    destinations = {m["Target"] for m in host.get("Mounts") or []}
    for bind in host.get("Binds") or []:
        parts = bind.split(":")
        if len(parts) > 1:
            destinations.add(parts[1])
    for mount in container.get("Mounts", []):
        if mount["Type"] == "volume" and mount["Destination"] not in destinations:
            if host.get("Mounts") is None:
                host["Mounts"] = []
            host["Mounts"].append({
                "Type": "volume", "Source": mount["Name"],
                "Target": mount["Destination"], "ReadOnly": not mount["RW"],
            })

    endpoints = {}
    container_id = container.get("Id", "")
    for name, network in container.get("NetworkSettings", {}).get("Networks", {}).items():
        endpoint = {
            key: copy.deepcopy(network[key])
            for key in ("IPAMConfig", "Links", "Aliases", "DriverOpts", "GwPriority")
            if network.get(key) is not None
        }
        if "Aliases" in endpoint:
            endpoint["Aliases"] = [
                alias for alias in endpoint["Aliases"]
                if alias not in (container_id, container_id[:12])
            ]
        endpoints[name] = endpoint
    config["HostConfig"] = host
    config["NetworkingConfig"] = {"EndpointsConfig": endpoints}
    return config


def prepare(container_name, image_name):
    container = docker_json("inspect", container_name)[0]
    image_id = docker_json("image", "inspect", image_name)[0]["Id"]
    config = create_config(container, image_id)
    path = docker_socket()
    version = request(path, "GET", "/version")["ApiVersion"]
    return {"socket": path, "version": version, "config": config}


def main():
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "prepare":
            json.dump(prepare(sys.argv[2], sys.argv[3]), sys.stdout)
        elif len(sys.argv) == 3 and sys.argv[1] == "create":
            saved = json.load(sys.stdin)
            request(
                saved["socket"], "POST",
                f'/v{saved["version"]}/containers/create?name={quote(sys.argv[2], safe="")}',
                saved["config"],
            )
        else:
            raise RuntimeError("usage: redeploy_config.py prepare CONTAINER IMAGE | create CONTAINER")
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException, RuntimeError) as exc:
        # Only deliberate, sanitized messages are safe to print.
        message = str(exc) if isinstance(exc, RuntimeError) else "could not access saved Docker settings or daemon"
        print(f"image-only update: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
