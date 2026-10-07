"""Deployment-hardening contracts for the shared-server move.

Phase 8B changed five things and none of them is visible in the running lab:
the Compose names it owns, the resource ceilings it runs under, the rotation
of its container logs, the fact that the training server refuses to relocate
itself, and the one dependency pin that Python 3.14 requires. Each of those is a
silent regression if it is undone - nothing fails loudly, the lab just quietly
becomes unsafe or undeployable again.

So these tests assert the properties themselves rather than restating the
files. Several deliberately parse `docker-compose.yml` as YAML instead of
grepping it, because the failure this guards against is a name that *looks*
right: an inherited default, or a value a service does not actually use.

The database used by the training-server tests is a throwaway in tmp_path.
`serve_training.main()` initialises a database before it validates the port, so
a test that invoked it against the default path would write to the real
`data/training.db`. That file is byte-identical before and after this suite and
there is a test asserting exactly that.
"""

import hashlib
import os
import re
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE = os.path.join(ROOT, "docker-compose.yml")
REQUIREMENTS = os.path.join(ROOT, "requirements.txt")
CONSTRAINTS = os.path.join(ROOT, "constraints.txt")
SERVE = os.path.join(ROOT, "scripts", "serve_training.py")
TRAINING_DB = os.path.join(ROOT, "data", "training.db")

PROJECT_NAME = "bcssl-siem-lab07"
CONTAINERS = {"bcssl-siem07-es", "bcssl-siem07-kibana"}
NETWORK_NAME = "bcssl-siem07-net"
VOLUMES = {"bcssl-siem07-es-data", "bcssl-siem07-kibana-config"}

#: Names that are unique across the whole Docker host rather than per project.
#: A service using one of these collides with any other stack on the machine.
FORBIDDEN_CONTAINER_NAMES = {"es", "kibana", "elasticsearch", "elasticsearch01"}

#: Resource ceilings. The point of the ceiling is blast radius on a shared host,
#: so a test that only checked "a limit exists" would pass on a number large
#: enough to take the machine down with it.
CPU_CEILING = {"elasticsearch": 2.0, "kibana": 1.0}
MEM_LIMIT = {"elasticsearch": 2 * 1024**3, "kibana": 1024**3}
MEM_CEILING_TOTAL = 4 * 1024**3  # the lab must start on ~3.5 GB total
ES_HEAP_MB = 512

#: SHA-256 of the files that must not change during deployment hardening. These
#: are the production student database and the grading key: a phase about Docker
#: names and resource ceilings has no business writing to either, and the test
#: that checks the training server does not open the real database needs a
#: recorded value to compare against.
ANSWER_KEY_SHA256 = "465fb8ae30aad2b5a55d13a7bc477db6d826876de101030c952e4fcd5a3fac4e"
TRAINING_DB_SHA256 = "4d853a59a547c513d3af4299b6c3d098562de162f13943ff149eae75b68f6027"


def _compose():
    """Parse the Compose file, skipping rather than failing if PyYAML is absent."""
    yaml = pytest.importorskip("yaml")
    with open(COMPOSE, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


# --------------------------------------------------------------------------
# A. Unique, project-specific names
# --------------------------------------------------------------------------

def test_the_compose_project_name_is_explicit_not_derived_from_the_directory():
    """Compose would otherwise name the project after the containing directory.

    On the server that directory belongs to a person, so the derived name is
    generic and able to collide with a sibling lab.
    """
    assert _compose()["name"] == PROJECT_NAME


def test_every_container_name_is_namespaced():
    names = {s.get("container_name") for s in _compose()["services"].values()}
    assert names == CONTAINERS


def test_no_service_uses_a_host_global_container_name():
    """`container_name` is unique per host, not per project.

    This is the specific blocker that stops a second lab from starting: a plain
    "es" makes `docker compose up` fail with "name already in use" the moment
    any other stack on the machine uses the same word.
    """
    for service, body in _compose()["services"].items():
        name = body.get("container_name")
        assert name, f"{service} has no explicit container_name"
        assert name not in FORBIDDEN_CONTAINER_NAMES, (
            f"{service} uses the host-global name {name!r}"
        )
        assert name.startswith("bcssl-siem07-"), (
            f"{service} container {name!r} is not namespaced to this lab"
        )


def test_the_network_is_named_explicitly_and_actually_attached():
    """An earlier revision declared a network no service referenced.

    Compose then silently used its auto-generated default, so the declared name
    did nothing at all. Asserting the declaration alone would not catch that,
    so this checks attachment as well.
    """
    compose = _compose()

    declared = compose["networks"]["siem-lab-net"]
    assert declared["name"] == NETWORK_NAME, "network name is not explicit"

    for service, body in compose["services"].items():
        assert "siem-lab-net" in body.get("networks", {}), (
            f"{service} does not attach to siem-lab-net; the declared network "
            f"would be dead configuration"
        )


def test_volumes_are_named_explicitly():
    named = {body["name"] for body in _compose()["volumes"].values()}
    assert named == VOLUMES


def test_the_data_volumes_still_mount_where_elasticsearch_expects_them():
    """Renaming a volume must not move where it is mounted inside the container."""
    mounts = {
        service: body.get("volumes", [])
        for service, body in _compose()["services"].items()
    }
    assert "es-data:/usr/share/elasticsearch/data" in mounts["elasticsearch"]
    assert "kibana-config:/usr/share/kibana/data" in mounts["kibana"]


# --------------------------------------------------------------------------
# B + C. Resource ceilings
# --------------------------------------------------------------------------

def test_each_service_has_a_cpu_ceiling_within_the_intended_range():
    """An uncapped service can starve the other labs sharing 16 cores."""
    services = _compose()["services"]
    for service, expected in CPU_CEILING.items():
        cpus = services[service].get("cpus")
        assert cpus is not None, f"{service} has no CPU limit"
        assert 0 < float(cpus) <= expected, (
            f"{service} CPU limit {cpus} exceeds the {expected}-core ceiling "
            f"this lab is allocated"
        )


def _bytes(value):
    """Compose accepts `2g`/`1g` as well as a byte count; normalise to int."""
    text = str(value).strip().lower()
    for suffix, scale in (("gib", 1024**3), ("mib", 1024**2),
                          ("gb", 1000**3), ("mb", 1000**2),
                          ("g", 1024**3), ("m", 1024**2), ("b", 1),
                          ("k", 1024)):
        if text.endswith(suffix):
            return int(float(text[: -len(suffix)]) * scale)
    return int(text)


def test_each_service_has_a_memory_limit_that_still_lets_the_lab_start():
    """The ceilings must total ~3.5 GB, not exceed the lab's stated budget."""
    services = _compose()["services"]
    total = 0
    for service, expected in MEM_LIMIT.items():
        limit = services[service].get("mem_limit")
        assert limit, f"{service} has no memory limit"
        assert 0 < _bytes(limit) <= expected, (
            f"{service} memory limit {limit} exceeds its {expected}-byte budget"
        )
        total += _bytes(limit)
    assert total <= MEM_CEILING_TOTAL, (
        f"combined memory ceilings {total} exceed what the lab is documented to "
        f"need; it could no longer start on a host with the expected RAM"
    )


def test_the_elasticsearch_heap_is_still_pinned_to_512mb():
    """512m heap plus ~1g off-heap is what fits inside the 2g container.

    Raising the heap without raising the limit proportionally reproduces the
    exact failure the pin exists to prevent: the JVM and its direct buffers
    cross the cgroup limit, the OOM killer sends SIGKILL, and Elasticsearch
    restarts in a loop that looks like a blank dashboard.
    """
    env = _compose()["services"]["elasticsearch"]["environment"]
    heap = next(e for e in env if e.startswith("ES_JAVA_OPTS="))
    assert f"-Xmx{ES_HEAP_MB}m" in heap, f"heap ceiling changed: {heap}"
    assert f"-Xms{ES_HEAP_MB}m" in heap, f"heap floor changed: {heap}"


def test_the_elasticsearch_image_version_is_unchanged():
    """Versions were explicitly held at 8.13.0 during the hardening phase."""
    assert _compose()["services"]["elasticsearch"]["image"].endswith(":8.13.0")
    assert _compose()["services"]["kibana"]["image"].endswith(":8.13.0")


def test_xpack_security_behaviour_is_unchanged():
    """This phase hardened isolation, not authentication.

    Changing either value here would silently alter the lab's security posture,
    which is a separate and much larger piece of work.
    """
    es_env = _compose()["services"]["elasticsearch"]["environment"]
    kib_env = _compose()["services"]["kibana"]["environment"]
    assert "xpack.security.enabled=false" in es_env
    assert "XPACK_SECURITY_ENABLED=false" in kib_env


# --------------------------------------------------------------------------
# D. Bounded container logging
# --------------------------------------------------------------------------

def test_both_services_rotate_their_container_logs():
    """Docker's default json-file driver neither caps nor rotates.

    On a host whose root filesystem is shared with nine other labs, unbounded
    container logs are a way to fill the disk.
    """
    for service, body in _compose()["services"].items():
        logging_cfg = body.get("logging")
        assert logging_cfg, f"{service} has no logging configuration"
        assert logging_cfg["driver"] == "json-file", service
        options = logging_cfg["options"]
        assert options["max-size"] == "10m", f"{service} max-size changed"
        assert options["max-file"] == "3", f"{service} max-file changed"


# --------------------------------------------------------------------------
# Network posture: unchanged, and load-bearing
# --------------------------------------------------------------------------

def test_elasticsearch_and_kibana_remain_loopback_only():
    """With xpack security disabled this binding is the only control standing
    between a student on the network and deleting the shared dataset."""
    for service, port in (("elasticsearch", 9200), ("kibana", 5601)):
        bindings = _compose()["services"][service]["ports"]
        assert bindings == [f"127.0.0.1:{port}:{port}"], (
            f"{service} port binding changed to {bindings}; it must stay on "
            f"loopback while authentication is disabled"
        )


def test_healthchecks_and_the_service_dependency_survived():
    services = _compose()["services"]
    for service in ("elasticsearch", "kibana"):
        assert services[service].get("healthcheck"), f"{service} lost its healthcheck"
        assert services[service].get("restart") == "unless-stopped", service
    depends = services["kibana"]["depends_on"]["elasticsearch"]
    assert depends["condition"] == "service_healthy"


# --------------------------------------------------------------------------
# E. The training server does not relocate itself
# --------------------------------------------------------------------------

def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _occupied_port():
    """A socket that is genuinely listening, and the port number it holds."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    return listener, listener.getsockname()[1]


def _port_can_be_bound(port):
    """True when nothing is listening on `port`.

    Deliberately a bind test rather than a connect test. Connecting cannot tell
    "a process is listening" apart from "the OS still holds this address in
    TIME_WAIT" - and on Windows `connect_ex` reports success against a
    TIME_WAIT socket, so a connect-based assertion detects whatever created
    that state, including the test's own setup. Binding without
    SO_REUSEADDR fails only when something is genuinely listening.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _serve(*args, db, timeout=90):
    return subprocess.run(
        [sys.executable, os.path.join("scripts", "serve_training.py"), *args, "--db", db],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout,
    )


def test_the_server_starts_when_the_requested_port_is_free(tmp_path):
    """The ordinary local case must be untouched by the hardening."""
    port = _free_port()
    db = str(tmp_path / "training.db")
    proc = subprocess.Popen(
        [sys.executable, os.path.join("scripts", "serve_training.py"),
         "--host", "127.0.0.1", "--port", str(port), "--db", db],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.time() + 45
        listening = False
        while time.time() < deadline and proc.poll() is None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    listening = True
                    break
            time.sleep(0.2)
        assert listening, (
            f"server never began listening on the requested port {port}; "
            f"stdout={proc.stdout.read() if proc.stdout else ''}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=20)


def test_the_server_refuses_to_start_on_an_occupied_port(tmp_path):
    """An occupied port is a configuration error and must stop the launch."""
    listener, port = _occupied_port()
    try:
        result = _serve("--host", "127.0.0.1", "--port", str(port),
                        db=str(tmp_path / "training.db"))
        assert result.returncode != 0, "occupied port did not fail the launch"
        assert str(port) in result.stderr, (
            f"error does not name the offending port: {result.stderr!r}"
        )
        assert "already in use" in result.stderr
    finally:
        listener.close()


def test_the_server_does_not_silently_move_to_the_next_port(tmp_path):
    """The regression this guards: walking forward to port+1..port+19.

    On a shared host that can land on another lab's port or a firewalled one,
    and it leaves the process listening somewhere its reverse proxy, systemd
    unit and documentation do not expect.

    Two independent signals are used, because either alone is weak. The
    process exiting at all is decisive on its own: had it relocated, it would
    reach serve_forever() and block until the subprocess timeout killed it, so
    a clean non-zero return already proves no listener was ever opened. The
    successor port is then checked as well, to name the specific failure.
    """
    listener, port = _occupied_port()
    next_port = port + 1
    try:
        result = _serve("--host", "127.0.0.1", "--port", str(port),
                        db=str(tmp_path / "training.db"), timeout=60)
        assert result.returncode != 0, (
            "the launch reported success on an occupied port"
        )
        assert "using" not in result.stdout, (
            f"server still reports relocating itself: {result.stdout!r}"
        )
        assert not _port_can_be_bound(port), (
            "test setup is wrong: the port under test is not actually held"
        )
        assert _port_can_be_bound(next_port), (
            f"something is listening on {next_port}; the server appears to have "
            f"relocated itself off the occupied port {port}"
        )
    finally:
        listener.close()


def test_the_port_fallback_loop_is_gone_from_the_source():
    """Belt and braces: the range walk must not reappear in any form."""
    source = open(SERVE, encoding="utf-8").read()
    assert not re.search(r"for\s+candidate\s+in\s+range", source), (
        "the port+1..port+19 walk has been reintroduced"
    )
    assert "is in use; using" not in source


def test_the_refusal_message_is_actionable():
    """The operator has to be told what to do, not merely that it failed."""
    source = open(SERVE, encoding="utf-8").read()
    assert "already in use" in source
    assert "--port" in source, "refusal does not say how to choose another port"


# --------------------------------------------------------------------------
# F. Dependency configuration is internally consistent
# --------------------------------------------------------------------------

def _pins(path):
    """Direct ``name==version`` pins, ignoring comments and blank lines."""
    pins = {}
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        match = re.fullmatch(r"([A-Za-z0-9._-]+)==([^\s;]+)", line)
        if match:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def test_every_direct_requirement_is_pinned_exactly():
    """An unpinned direct dependency makes the install non-reproducible."""
    pins = _pins(REQUIREMENTS)
    for package in ("elasticsearch", "pyyaml", "apscheduler", "requests", "urllib3"):
        assert package in pins, f"{package} is not pinned"
    for line in open(REQUIREMENTS, encoding="utf-8"):
        stripped = line.split("#", 1)[0].strip()
        if stripped and not stripped.startswith("-"):
            assert "==" in stripped, f"unpinned requirement: {stripped!r}"


def test_pyyaml_is_pinned_to_the_first_release_with_a_cpython_314_wheel():
    """6.0.1 shipped wheels only to cp312.

    On CPython 3.14 pip would fall back to building the C extension from source,
    which needs python3.14-dev, libyaml-dev and a C compiler - on a host where
    sudo is restricted. 6.0.3 is the first release publishing cp314 wheels.
    """
    assert _pins(REQUIREMENTS)["pyyaml"] == "6.0.3"


def test_no_requirement_still_pins_a_pyyaml_without_a_cpython_314_wheel():
    """Guards the pin itself rather than the version string.

    Checked against the requirement lines only: the explanatory comment above
    them legitimately mentions 6.0.1 to say why it was moved, so a substring
    search over the whole file would match its own documentation.
    """
    stale = {"6.0", "6.0.1", "6.0.2"}
    for line in open(REQUIREMENTS, encoding="utf-8"):
        code = line.split("#", 1)[0].strip()
        if not code.lower().startswith("pyyaml=="):
            continue
        assert code.split("==", 1)[1] not in stale, (
            f"{code!r} has no cp314 wheel; 6.0.3 is the first release with one"
        )


def test_the_constraints_file_never_contradicts_a_direct_requirement():
    """A constraints file cannot override a direct requirement.

    If the two disagreed, pip reports a conflict instead of resolving it, so a
    drifting constraints file breaks the install it was written to stabilise.
    """
    direct = _pins(REQUIREMENTS)
    constraints = _pins(CONSTRAINTS)
    assert constraints, "constraints.txt pins nothing"
    for package, version in constraints.items():
        if package in direct:
            assert direct[package] == version, (
                f"{package} is {direct[package]} in requirements.txt but "
                f"{version} in constraints.txt; pip would refuse to resolve"
            )


def test_the_constraints_file_pins_the_packages_requirements_leaves_floating():
    """The whole point: the transitives nobody was pinning before."""
    constraints = _pins(CONSTRAINTS)
    for package in ("elastic-transport", "certifi", "charset-normalizer", "idna",
                    "six", "pytz", "tzlocal", "coverage"):
        assert package in constraints, f"{package} is left floating"


# --------------------------------------------------------------------------
# Protected state
# --------------------------------------------------------------------------

def test_running_the_suite_does_not_touch_the_real_student_database():
    """`serve_training.main()` opens a database before it validates the port.

    The training-server tests therefore pass --db tmp_path/"training.db". If
    one of them ever dropped that flag, it would write to the production
    database, so the production file's hash is pinned and compared.
    """
    digest = hashlib.sha256(open(TRAINING_DB, "rb").read()).hexdigest()
    assert digest == TRAINING_DB_SHA256, (
        "data/training.db changed on disk. Something in this phase, or in the "
        "tests, wrote to the production student database."
    )


def test_the_answer_key_is_unchanged():
    digest = hashlib.sha256(
        open(os.path.join(ROOT, "data", "answer-key.json"), "rb").read()
    ).hexdigest()
    assert digest == ANSWER_KEY_SHA256, (
        "data/answer-key.json changed. Nothing in the deployment-hardening "
        "phase may touch grading content."
    )
