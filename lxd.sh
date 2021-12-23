export LXD_IMAGE_BASE_NAME="ucs5"
export LXD_IMAGE_BASE_VERSION="5.0-1e176"
export LXD_IMAGE_NAME="$LXD_IMAGE_BASE_NAME-$LXD_IMAGE_BASE_VERSION"
export LXD_IMAGE_BASE_URL="https://download.software-univention.de/download/tarballs"
export LXD_IMAGE_FILES_HASHES="$LXD_IMAGE_NAME.SHA256"
export LXD_IMAGE_FILE_METADATA="$LXD_IMAGE_NAME-metadata.tar.xz"
export LXD_IMAGE_FILE_ROOTFS="$LXD_IMAGE_NAME.tar.xz"


lxd_is_initialized () {
    lxc profile show default | grep -q pool
}

download_lxd_image_files () {
    wget -c "$LXD_IMAGE_BASE_URL/$LXD_IMAGE_FILES_HASHES" "$LXD_IMAGE_BASE_URL/$LXD_IMAGE_FILE_METADATA" "$LXD_IMAGE_BASE_URL/$LXD_IMAGE_FILE_ROOTFS"
}

verify_lxd_image_files () {
    sha256sum -c "$LXD_IMAGE_FILES_HASHES"
}

lxd_create_image_from_files () {
    lxc image import "$LXD_IMAGE_FILE_METADATA" "$LXD_IMAGE_FILE_ROOTFS" --alias "$LXD_IMAGE_NAME"
}

lxd_image_exists () {
  lxc image list | grep -Eq "$LXD_IMAGE_NAME.*x86_64"
}

lxd_image_files_exists () {
  ls "$LXD_IMAGE_FILES_HASHES" "$LXD_IMAGE_FILE_METADATA" "$LXD_IMAGE_FILE_ROOTFS" 1>&2 >/dev/null
}

lxd_create_container () {
    lxc launch "$LXD_IMAGE_NAME" "$LXD_IMAGE_BASE_NAME" -c security.privileged=true -c security.nesting=true -c raw.lxc=lxc.apparmor.profile=unconfined
}

lxd_start_container () {
    lxc start "$LXD_IMAGE_BASE_NAME"
}

lxd_stop_container () {
    lxc stop "$LXD_IMAGE_BASE_NAME"
}

lxd_remove_container () {
    lxc delete "$LXD_IMAGE_BASE_NAME"
}

lxd_remove_image () {
    lxc image delete "$LXD_IMAGE_NAME"
}

lxd_container_stopped () {
  lxc list | grep -Eq "$LXD_IMAGE_BASE_NAME.*STOPPED"
}

lxd_container_running () {
  lxc list | grep -Eq "$LXD_IMAGE_BASE_NAME.*RUNNING"
}

lxd_container_running_with_ip () {
  lxc list | grep -Eq "$LXD_IMAGE_BASE_NAME.*RUNNING.*eth0"
}

lxd_container_ip () {
    RES="$(lxc info ucs5 | yq e '.Resources.["Network usage"].eth0.["IP addresses"].inet' - | cut -d '/' -f 1)"
    if [ "$RES" != "null" ]; then
        echo "$RES"
    fi
}

yq_is_installed () {
    which yq > /dev/null
}

get_openapi_schema () {
  curl -s --fail -u Administrator:univention -X GET http://$(lxd_container_ip)/univention/udm/openapi.json
}
