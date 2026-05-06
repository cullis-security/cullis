# Custom Python derivations for the broker — the bits the Cullis
# stack imports that aren't in nixpkgs yet. ``a2a-sdk`` is the
# headline missing piece; ``culsans`` and ``aiologic`` come along
# for the ride as transitive deps. All three are pure-Python with
# hatchling-based builds, so the derivations here are short.
#
# Caller takes ``pkgs`` and returns an attrset of finished
# packages, ready to drop into ``pkgs.python311.withPackages``.
# Pinned to specific PyPI versions + sdist hashes so the closure
# is reproducible — bumping is a deliberate edit, not a network
# fetch.
{ pkgs }:

let
  py = pkgs.python311Packages;

  # Async sync primitives library (used by culsans).
  aiologic = py.buildPythonPackage rec {
    pname = "aiologic";
    version = "0.16.0";
    pyproject = true;
    src = py.fetchPypi {
      inherit pname version;
      hash = "sha256-wmfMvT/0F+yT540o1NV3zMoRXVeXzb0WeFpVHZZYhY8=";
    };
    nativeBuildInputs = [ py.hatchling py.hatch-vcs ];
    env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
    propagatedBuildInputs = with py; [
      sniffio
      typing-extensions
      wrapt
    ];
    # Upstream's tests need the optional ``trio`` / ``curio`` extras
    # that aren't in our closure. The package itself is exercised
    # transitively by the broker boot path; that's the actual test.
    doCheck = false;
    pythonImportsCheck = [ "aiologic" ];
  };

  # Mixed sync/async queue + lock primitives. Required by a2a-sdk
  # only when ``python_full_version < "3.13"``; the test VM ships
  # 3.11, so we always pull it in.
  culsans = py.buildPythonPackage rec {
    pname = "culsans";
    version = "0.11.0";
    pyproject = true;
    src = py.fetchPypi {
      inherit pname version;
      hash = "sha256-C0PQ0F3OYQYpPRFMhuP7S/xjCIz+j/CO0/42iRRH/jM=";
    };
    nativeBuildInputs = [ py.hatchling py.hatch-vcs ];
    propagatedBuildInputs = [
      aiologic
      py.typing-extensions
    ];
    # ``hatch-vcs`` reads the version from a tag; the sdist already
    # carries a baked ``_version.py`` so we hand-set this and skip
    # the VCS lookup (sdist isn't a git checkout).
    env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
    doCheck = false;
    pythonImportsCheck = [ "culsans" ];
  };

  # The Google A2A Protocol Python SDK. Used by ``app/a2a/agent_card.py``
  # to render agent cards over the A2A wire; without it the broker
  # ``import`` chain breaks at module load.
  #
  # Upstream uses ``uv-dynamic-versioning`` which isn't in nixpkgs.
  # We patch the pyproject to declare a static version + drop the
  # plugin from the build-system requires; the resulting wheel is
  # functionally identical.
  a2a-sdk = py.buildPythonPackage rec {
    pname = "a2a-sdk";
    version = "1.0.2";
    pyproject = true;
    src = py.fetchPypi {
      pname = "a2a_sdk";
      inherit version;
      hash = "sha256-5O5N1QmJTDLJpt9ygxmHX6TwSecK6CR2+kRzU+Oktkg=";
    };
    postPatch = ''
      substituteInPlace pyproject.toml \
        --replace 'dynamic = ["version"]' 'version = "${version}"' \
        --replace '"hatchling", "uv-dynamic-versioning"' '"hatchling"' \
        --replace 'source = "uv-dynamic-versioning"' '# source = "uv-dynamic-versioning" — patched out for nix'
    '';
    nativeBuildInputs = [ py.hatchling ];
    propagatedBuildInputs = with py; [
      culsans
      google-api-core
      googleapis-common-protos
      httpx
      httpx-sse
      json-rpc
      packaging
      protobuf
      pydantic
    ];
    doCheck = false;
    pythonImportsCheck = [ "a2a" ];
  };

in
{
  inherit aiologic culsans a2a-sdk;
}
