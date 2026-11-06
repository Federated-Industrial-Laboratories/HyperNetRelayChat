use super::*;

#[test]
fn model_definition_reuses_local_adapter_limits_and_refuses_external_destinations() {
    let mut config = Config::new().unwrap();
    config.curl = PathBuf::from("/usr/bin/curl");
    config.validate().unwrap();
    config.endpoint = "192.0.2.10:8080".parse().unwrap();
    assert!(config.validate().is_err());
    config.endpoint = "127.0.0.1:8080".parse().unwrap();
    config.model = "qwen:cloud".into();
    assert!(config.validate().is_err());
    config.model = "Qwen".into();
    config.output_tokens = config.context_tokens;
    assert!(config.validate().is_err());
}

#[test]
fn managed_backends_pin_locality_and_keep_paths_as_single_arguments() {
    let mut config = Config::new().unwrap();
    config.backend = Backend::LlamaCpp {
        executable: "/usr/bin/llama-server".into(),
        model_file: "/models/space and $sign.gguf".into(),
        gpu_layers: 0,
        cuda_devices: "1".into(),
    };
    let (_, args, environment) = launch(&config).unwrap();
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--model", "/models/space and $sign.gguf"])
    );
    assert!(args.contains(&"--offline".into()) && args.contains(&"--log-disable".into()));
    assert!(args.windows(2).any(|pair| pair == ["--host", "127.0.0.1"]));
    assert!(environment.contains(&("CUDA_VISIBLE_DEVICES".into(), "1".into())));
    config.backend = Backend::Ollama {
        executable: "/usr/bin/ollama".into(),
        models_directory: "/models/ollama".into(),
        cuda_devices: String::new(),
    };
    let (_, args, environment) = launch(&config).unwrap();
    assert_eq!(args, ["serve"]);
    assert!(environment.contains(&("OLLAMA_NO_CLOUD".into(), "1".into())));
    assert!(environment.contains(&("OLLAMA_HOST".into(), "127.0.0.1:8080".into())));
    config.backend = Backend::External;
    assert!(launch(&config).is_err());
}

#[test]
fn transitional_process_states_prevent_definition_edits() {
    for state in ["active", "activating", "reloading", "deactivating"] {
        assert!(running(&units::Status {
            active: state == "active",
            state: state.into(),
            ..Default::default()
        }));
    }
    assert!(running(&units::Status {
        pid: 123,
        state: "failed".into(),
        ..Default::default()
    }));
    assert!(!running(&units::Status {
        state: "stopped".into(),
        ..Default::default()
    }));
}
