# to be sourced by build_ucs_join_image or build_udm_rest_api_only_image

if [ -z "$UCS_REPOS" ]; then
  echo "'UCS_REPOS' unset. Setting to 'stable'."
  UCS_REPOS="stable"
fi

export DOCKER_REGISTRY="docker-upload.software-univention.de"
export UCS_VERSION="4.4-8"


if [ "$UCSSCHOOL" = 1 ]; then
    BASE_NAME="ucs-master-amd64-joined-ucsschool"
else
    BASE_NAME="ucs-master-amd64-joined"
fi
export UCS_JOINED_TARGET_DOCKER_IMG="${DOCKER_REGISTRY}/${BASE_NAME}"
export UCS_JOINED_TARGET_DOCKER_IMG_VERSION="${UCS_JOINED_TARGET_DOCKER_IMG}:${UCS_REPOS}-${UCS_VERSION}"
export UCS_JOINED_TARGET_DOCKER_IMG_LATEST="${UCS_JOINED_TARGET_DOCKER_IMG}:${UCS_REPOS}-latest"

export UDM_ONLY_PARENT_DOCKER_IMG="${BASE_NAME}"
export UDM_ONLY_TARGET_DOCKER_IMG="${DOCKER_REGISTRY}/${UDM_ONLY_PARENT_DOCKER_IMG}-udm-rest-api-only"
export UDM_ONLY_TARGET_DOCKER_IMG_VERSION="${UDM_ONLY_TARGET_DOCKER_IMG}:${UCS_REPOS}-${UCS_VERSION}"
export UDM_ONLY_TARGET_DOCKER_IMG_LATEST="${UDM_ONLY_TARGET_DOCKER_IMG}:${UCS_REPOS}-latest"

docker_img_exists () {
  local IMG="${1?:Missing image name}"
  [ -z "$IMG" ] && return 1
  docker images "$IMG" | grep -E -q -v '^REPOSITORY' && return 0
}

docker_container_running () {
  local CONTAINER="${1?:Missing container name}"
  [ -z "$CONTAINER" ] && return 1
  docker ps --filter name="$CONTAINER" | grep -E -q -v '^CONTAINER' && return 0
}

docker_container_ip () {
  local CONTAINER="${1?:Missing container name}"
  [ -z "$CONTAINER" ] && echo "Empty container name" && return 1
  docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER"
}

get_openapi_schema () {
  local CONTAINER="${1?:Missing container name}"
  [ -z "$CONTAINER" ] && echo "Empty container name" && return 1
  if [ -z "$UCS_CONTAINER_IP" ]; then
    export UCS_CONTAINER_IP=$(docker_container_ip "$CONTAINER")
  fi
  [ -z "$UCS_CONTAINER_IP" ] && echo "Empty container IP" && return 1
  curl -s --fail -u Administrator:univention -X GET http://$UCS_CONTAINER_IP/univention/udm/openapi.json
}
