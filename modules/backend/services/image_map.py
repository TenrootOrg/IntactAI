"""Which docker images belong to which module.

Relocated out of services/upgrade/package.py when the upgrade engine moved to
the host. app.py calls module_image_repos() on every boot to reclaim the
images of modules the operator has disabled -- nothing to do with upgrading,
and it would have gone down with the deletion.
"""

PRIMARY_IMAGES = {
    'elk': [
        ('docker.elastic.co/elasticsearch/elasticsearch:{version}',
         'elasticsearch-{version}.tar'),
        ('docker.elastic.co/kibana/kibana:{version}',
         'kibana-{version}.tar'),
        ('docker.elastic.co/logstash/logstash:{version}',
         'logstash-{version}.tar'),
    ],
    'timesketch': [
        ('us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:{version}',
         'timesketch-{version}.tar'),
    ],
    'plaso': [
        ('log2timeline/plaso:{version}', 'plaso-{version}.tar'),
    ],
    'iris': [
        # iris-worker reuses the same iriswebapp_app image. The DB image
        # is included for air-gap support; data lives in a volume so the
        # upgrade is non-destructive.
        ('ghcr.io/dfir-iris/iriswebapp_app:{version}',
         'iris-app-{version}.tar'),
        ('ghcr.io/dfir-iris/iriswebapp_nginx:{version}',
         'iris-nginx-{version}.tar'),
        ('ghcr.io/dfir-iris/iriswebapp_db:{version}',
         'iris-db-{version}.tar'),
    ],
    'o365rc': [
        # Upstream only ships ':latest', so {version} is normally 'latest'.
        ('anssi/dfir-o365rc:{version}', 'dfir-o365rc-{version}.tar'),
    ],
    'volweb': [
        # forensicxlab releases backend + frontend in lockstep so a single
        # `versions.volweb` pin drives both.
        ('forensicxlab/volweb-backend:{version}',
         'volweb-backend-{version}.tar'),
        ('forensicxlab/volweb-frontend:{version}',
         'volweb-frontend-{version}.tar'),
    ],
    'portainer': [
        # Portainer's own docs require the agent to match the server's
        # version exactly — one `versions.portainer` pin drives both.
        ('portainer/portainer-ce:{version}', 'portainer-ce-{version}.tar'),
        ('portainer/agent:{version}', 'portainer-agent-{version}.tar'),
    ],
}

TRANSITIVE_IMAGES = {
    'timesketch': [
        ('postgres',   'postgres:{tag}',                       'postgres-{tag}.tar'),
        ('opensearch', 'opensearchproject/opensearch:{tag}',   'opensearch-{tag}.tar'),
        ('redis',      'redis:{tag}',                          'redis-{tag}.tar'),
        ('nginx',      'nginx:{tag}',                          'nginx-{tag}.tar'),
    ],
    'iris': [
        # Infrastructure dep — IRIS compose pulls rabbitmq from Docker
        # Hub at compose-up time. Bundling lets the apply step load it
        # offline.
        ('rabbitmq', 'rabbitmq:{tag}', 'rabbitmq-{tag}.tar'),
    ],
    'volweb': [
        # Distinct tar names from timesketch's postgres/redis so both
        # bundles can coexist on disk without name collisions.
        ('postgres', 'postgres:{tag}', 'volweb-postgres-{tag}.tar'),
        ('redis',    'redis:{tag}',    'volweb-redis-{tag}.tar'),
    ],
}

def module_image_repos(module: str):
    """Docker repository names a module's images live under, tags stripped.

    For reclaiming images belonging to a module that is switched off. The
    tables store full patterns ("ghcr.io/dfir-iris/iriswebapp_app:{version}");
    what a `docker images <repo>` filter wants is the part before the tag.

    Includes TRANSITIVE deps, which is where the space actually is -- IRIS's
    rabbitmq is 176 MB on its own. Several of those repos are SHARED (both
    timesketch and volweb use postgres and redis), so a caller must never
    delete on the strength of this list alone: check that no container
    references the image first. Naming a repo here says "this module can own
    images under it", not "this module owns them exclusively".
    """
    # rsplit on the LAST ':' -- the tag placeholder is always final, and a
    # registry host may legitimately carry a port (host:5000/repo:{version}).
    repos = [p.rsplit(':', 1)[0] for p, _tar in (PRIMARY_IMAGES.get(module) or [])]
    repos += [p.rsplit(':', 1)[0]
              for _dep, p, _tar in (TRANSITIVE_IMAGES.get(module) or [])]
    # dedupe, preserve order
    seen, out = set(), []
    for r in repos:
        if r and r not in seen:
            seen.add(r); out.append(r)
    return out

def image_owner_prefixes():
    """{tar-filename prefix: owning module}, derived from the tables above.

    The manifest records `contents.image_sizes` keyed by FILENAME with no
    module attribution, so anything that needs to know which module an image
    belongs to has to reconstruct it. Matching on the PREFIX -- the part of
    the tar pattern before the version placeholder -- rather than rendering
    the exact filename avoids depending on version-string normalisation:
    velociraptor strips a leading 'v', o365rc uses the literal 'latest', and
    a rendering mismatch would silently orphan an image (counted as nobody's,
    so never pruned and never budgeted).

    Prefixes are collision-free by construction -- volweb's sidecars are named
    volweb-postgres-/volweb-redis- precisely so they do not collide with
    timesketch's postgres-/redis-, and iris-nginx- does not collide with
    timesketch's nginx-. Callers resolve longest-prefix-first anyway.
    """
    prefixes = {}
    for module, entries in PRIMARY_IMAGES.items():
        for _image, tar_pattern in entries:
            prefixes[tar_pattern.split('{')[0]] = module
    for module, entries in TRANSITIVE_IMAGES.items():
        for _dep, _image, tar_pattern in entries:
            prefixes[tar_pattern.split('{')[0]] = module
    # The platform's own images. Not in either table: they are written
    # directly by the packager (see the intact-backend / tusd blocks below).
    prefixes['intact-backend-'] = 'intact'
    prefixes['tusd-'] = 'intact'
    # Velociraptor's server image is BUILT locally rather than pulled, so it is
    # in neither table -- the packager names the tar itself. Without this it
    # resolves to no owner and would be excluded from both pruning and the disk
    # budget.
    prefixes['velociraptor-'] = 'velociraptor'
    # aws_sigma ships a DATA tar (the SigmaHQ rule pack), also written directly
    # by the packager rather than coming from either table. It was ownerless
    # until now, which was survivable only while aws_sigma was excluded from
    # releases: an ownerless file is never pruned and never budgeted. Now that
    # it ships as its own asset, that asset's entire payload would have been
    # unattributable.
    #
    # BOTH spellings stay mapped. `aws_sigma-` is what the packager writes now;
    # `cloudtrail-` is what every package built before the module rename
    # carries, and this box can be handed one of those. Dropping the old prefix
    # would make that pack ownerless again — silently un-pruned and
    # un-budgeted, which is the exact failure this entry was added to fix.
    prefixes['aws_sigma-'] = 'aws_sigma'
    prefixes['cloudtrail-'] = 'aws_sigma'
    # The platform's main reverse proxy (modules/nginx/, intact_nginx). It is
    # deliberately NOT named `nginx-<tag>.tar`: that prefix belongs to
    # timesketch's own nginx (TRANSITIVE_IMAGES above), this dict is keyed by
    # prefix, and reusing it would silently reassign timesketch's image --
    # after which the unselected-module prune would delete it on any apply
    # that deselects timesketch. `intact-nginx-` is unambiguous, and since
    # lookup is longest-prefix-first it cannot shadow `intact-backend-` either.
    prefixes['intact-nginx-'] = 'intact'
    return prefixes

def images_by_module(image_names):
    """{module: [filename, ...]} for the given image tar names.

    Unattributable names map under None so callers can see them rather than
    silently dropping them -- an image nobody owns is a packaging bug, and
    treating it as ownerless is safer than guessing (pruning it could delete
    something a module needs).
    """
    prefixes = sorted(image_owner_prefixes().items(), key=lambda kv: -len(kv[0]))
    out = {}
    for name in image_names or []:
        owner = next((m for p, m in prefixes if name.startswith(p)), None)
        out.setdefault(owner, []).append(name)
    return out
