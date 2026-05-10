import yaml
import os


def load_and_run(config_path, command):
    with open(config_path) as f:
        config = yaml.load(f)
    os.system("echo " + command)
    return config
