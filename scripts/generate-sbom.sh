#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <output.cdx.json>" >&2
  exit 2
fi

version="$1"
output="$2"
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version: ${version}" >&2
  exit 2
fi
command -v jq >/dev/null || {
  echo "jq is required to generate the SBOM" >&2
  exit 1
}

metadata_file="$(mktemp)"
output_temporary=""
cleanup() {
  rm -f "${metadata_file}"
  if [[ -n "${output_temporary}" ]]; then
    rm -f "${output_temporary}"
  fi
}
trap cleanup EXIT HUP INT TERM

output_directory="$(dirname "${output}")"
mkdir -p "${output_directory}"
if [[ ! -d "${output_directory}" || -L "${output_directory}" ]]; then
  echo "SBOM output directory must be a real directory: ${output_directory}" >&2
  exit 1
fi
output_name="$(basename "${output}")"
output_temporary="$(mktemp "${output_directory}/.${output_name}.XXXXXX")"

cargo metadata --locked --format-version 1 > "${metadata_file}"
cargo_version="$(jq -r '.packages[] | select(.name == "auto-proxy") | .version' "${metadata_file}")"
if [[ "${cargo_version}" != "${version}" ]]; then
  echo "SBOM version ${version} does not match Cargo package ${cargo_version}" >&2
  exit 1
fi

timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
if command -v uuidgen >/dev/null 2>&1; then
  sbom_uuid="$(uuidgen)"
elif [[ -r /proc/sys/kernel/random/uuid ]]; then
  sbom_uuid="$(< /proc/sys/kernel/random/uuid)"
else
  echo "uuidgen or /proc/sys/kernel/random/uuid is required to generate an SBOM serial" >&2
  exit 1
fi
serial_number="urn:uuid:$(printf '%s' "${sbom_uuid}" | tr '[:upper:]' '[:lower:]')"

jq \
  --arg timestamp "${timestamp}" \
  --arg serial_number "${serial_number}" \
  --arg version "${version}" '
    def purl:
      "pkg:cargo/\(.name)@\(.version)";
    def component:
      {
        type: "library",
        "bom-ref": purl,
        name: .name,
        version: .version,
        purl: purl
      }
      + if .license == null then {} else {licenses: [{expression: .license}]} end;
    def non_dev_dependencies($nodes; $ids):
      [
        $nodes[]
        | select(.id as $id | $ids | index($id))
        | .deps[]
        | select(any(.dep_kinds[]; .kind != "dev"))
        | .pkg
      ]
      | unique;
    def dependency_closure($nodes; $ids):
      (non_dev_dependencies($nodes; $ids)) as $dependencies
      | (($ids + $dependencies) | unique) as $expanded
      | if ($expanded | length) == ($ids | length)
        then $expanded
        else dependency_closure($nodes; $expanded)
        end;

    . as $metadata
    | ($metadata.resolve.root // $metadata.workspace_members[0]) as $root
    | ($metadata.packages | map({key: .id, value: .}) | from_entries) as $packages
    | (dependency_closure($metadata.resolve.nodes; [$root])) as $included
    | {
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        serialNumber: $serial_number,
        version: 1,
        metadata: {
          timestamp: $timestamp,
          component: (
            $packages[$root]
            | component
            | .type = "application"
            | .name = "ap"
            | .version = $version
          )
        },
        components: [
          $metadata.packages[]
          | select(.id != $root and (.id as $id | $included | index($id)))
          | component
        ] | sort_by(.purl),
        dependencies: [
          $metadata.resolve.nodes[]
          | select(.id as $id | $included | index($id))
          | . as $node
          | {
              ref: ($packages[$node.id] | purl),
              dependsOn: (
                [
                  $node.deps[]
                  | select(any(.dep_kinds[]; .kind != "dev"))
                  | .pkg
                  | select(. as $id | $included | index($id))
                  | $packages[.]
                  | purl
                ]
                | unique
                | sort
              )
            }
        ] | sort_by(.ref)
      }
  ' "${metadata_file}" > "${output_temporary}"

jq -e '
  .bomFormat == "CycloneDX"
  and .specVersion == "1.5"
  and .metadata.component.name == "ap"
  and (.components | length > 0)
' "${output_temporary}" >/dev/null

chmod 0644 "${output_temporary}"
mv -f -- "${output_temporary}" "${output}"
