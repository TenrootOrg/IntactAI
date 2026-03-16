#!/bin/bash
# MSSP Platform Installer - Configuration Functions
# Config reading, validation, and env file updates

# ============================================================================
# Configuration Reading
# ============================================================================

check_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Config file not found: $CONFIG_FILE"
        exit 1
    fi
    log_success "Config file found"
}

# Read value from config.yaml
# Usage: value=$(read_config "['domain']")
read_config() {
    local key="$1"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo ""
        return 1
    fi

    python3 -c "import yaml; print(yaml.safe_load(open('${CONFIG_FILE}'))${key})" 2>/dev/null || echo ""
}

# ============================================================================
# Environment File Updates
# ============================================================================

# Update a single variable in an env file
# Usage: update_env_var "file" "VAR_NAME" "value"
update_env_var() {
    local env_file="$1"
    local var_name="$2"
    local var_value="$3"

    if [[ ! -f "$env_file" ]]; then
        log_warn "Env file not found: $env_file"
        return 1
    fi

    if grep -q "^${var_name}=" "$env_file"; then
        sed -i "s|^${var_name}=.*|${var_name}=${var_value}|" "$env_file"
    else
        log_warn "Variable ${var_name} not found in ${env_file}"
        return 1
    fi
}

update_env_files() {
    log_info "Updating .env files from config.yaml..."

    local domain=$(read_config "['domain']")

    # Velociraptor - update domain/IP and version
    local velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if is_enabled "$velo_enabled"; then
        local velo_env="${SCRIPT_DIR}/modules/velociraptor/.env"
        if [[ -f "$velo_env" ]]; then
            local velo_version=$(read_config "['versions']['velociraptor']")
            local velo_user=$(read_config "['modules']['velociraptor']['id']")
            local velo_pass=$(read_config "['modules']['velociraptor']['password']")
            local velo_api_user=$(read_config "['modules']['velociraptor']['api_id']")
            local velo_api_pass=$(read_config "['modules']['velociraptor']['api_password']")

            # Extract major.minor tag from version (e.g., "0.75.6" -> "0.75")
            local velo_tag=$(echo "$velo_version" | sed 's/^\([0-9]*\.[0-9]*\).*/\1/')
            update_env_var "$velo_env" "VELOCIRAPTOR_TAG" "$velo_tag"
            update_env_var "$velo_env" "VELOCIRAPTOR_VERSION" "$velo_version"
            update_env_var "$velo_env" "VELOX_USER" "$velo_user"
            update_env_var "$velo_env" "VELOX_PASSWORD" "$velo_pass"
            update_env_var "$velo_env" "VELOX_USER_2" "$velo_api_user"
            update_env_var "$velo_env" "VELOX_PASSWORD_2" "$velo_api_pass"
            update_env_var "$velo_env" "VELOX_FRONTEND_HOSTNAME" "$domain"
            update_env_var "$velo_env" "VELOX_PUBLIC_IP" "$domain"
            update_env_var "$velo_env" "VELOX_SERVER_URL" "https://${domain}:8000/"
            log_success "Updated Velociraptor .env"
        else
            log_warn "Velociraptor .env not found, skipping"
        fi
    fi

    # TimeSketch - update version and credentials
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if is_enabled "$ts_enabled"; then
        local ts_env="${SCRIPT_DIR}/modules/timesketch/.env"
        if [[ -f "$ts_env" ]]; then
            local ts_version=$(read_config "['versions']['timesketch']")
            local ts_user=$(read_config "['modules']['timesketch']['id']")
            local ts_pass=$(read_config "['modules']['timesketch']['password']")

            update_env_var "$ts_env" "TIMESKETCH_VERSION" "$ts_version"
            update_env_var "$ts_env" "TIMESKETCH_USER" "$ts_user"
            update_env_var "$ts_env" "TIMESKETCH_PASSWORD" "$ts_pass"
            log_success "Updated TimeSketch .env"
        else
            log_warn "TimeSketch .env not found, skipping"
        fi
    fi

    # IRIS - update version
    local iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if is_enabled "$iris_enabled"; then
        local iris_env="${SCRIPT_DIR}/modules/iris/.env"
        if [[ -f "$iris_env" ]]; then
            local iris_version=$(read_config "['versions']['iris']")
            update_env_var "$iris_env" "IRIS_VERSION" "$iris_version"
            log_success "Updated IRIS .env"
        else
            log_warn "IRIS .env not found, skipping"
        fi
    fi

    # ELK - update version and credentials
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if is_enabled "$elk_enabled"; then
        local elk_env="${SCRIPT_DIR}/modules/elk/.env"
        if [[ -f "$elk_env" ]]; then
            local elk_version=$(read_config "['versions']['elk']")
            local elk_pass=$(read_config "['modules']['elk']['password']")

            update_env_var "$elk_env" "ELASTIC_VERSION" "$elk_version"
            update_env_var "$elk_env" "KIBANA_VERSION" "$elk_version"
            update_env_var "$elk_env" "ELASTIC_PASSWORD" "$elk_pass"
            update_env_var "$elk_env" "KIBANA_PASSWORD" "$elk_pass"
            log_success "Updated ELK .env"
        else
            log_warn "ELK .env not found, skipping"
        fi
    fi

    # Portainer - update version
    local portainer_enabled=$(read_config "['modules']['portainer']['enabled']")
    if is_enabled "$portainer_enabled"; then
        local portainer_env="${SCRIPT_DIR}/modules/portainer/.env"
        if [[ -f "$portainer_env" ]]; then
            local portainer_version=$(read_config "['versions']['portainer']")
            update_env_var "$portainer_env" "PORTAINER_VERSION" "$portainer_version"
            log_success "Updated Portainer .env"
        else
            log_warn "Portainer .env not found, skipping"
        fi
    fi

    # Backend - update credentials and Plaso version
    local backend_env="${SCRIPT_DIR}/modules/backend/.env"
    if [[ -f "$backend_env" ]]; then
        local ts_user=$(read_config "['modules']['timesketch']['id']")
        local ts_pass=$(read_config "['modules']['timesketch']['password']")
        local plaso_version=$(read_config "['versions']['plaso']")

        update_env_var "$backend_env" "TIMESKETCH_USER" "$ts_user"
        update_env_var "$backend_env" "TIMESKETCH_PASS" "$ts_pass"
        update_env_var "$backend_env" "PLASO_VERSION" "$plaso_version"
        log_success "Updated Backend .env"
    else
        log_warn "Backend .env not found, skipping"
    fi
}

# ============================================================================
# Data Directory Setup
# ============================================================================

create_data_directory() {
    log_info "Creating data directory for SQLite database..."

    local data_dir="${SCRIPT_DIR}/data"

    # Create data directory if it doesn't exist
    if [[ ! -d "$data_dir" ]]; then
        mkdir -p "$data_dir"
        log_success "Created data directory: $data_dir"
    else
        log_info "Data directory already exists: $data_dir"
    fi

    # Set proper permissions (readable/writable by all)
    chmod 755 "$data_dir"

    log_success "Data directory ready (SQLite database will be created on first startup)"
}
