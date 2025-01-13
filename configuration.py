from typing import TypedDict
import json

CONFIGURATION_FILE = "configuration.json"
BC_CONFIGURATION_FILE = "bc_configuration.json"

class Configuration(TypedDict):
    index: int
    threshold: int
    total_signers: int
    urls: dict
    public_key: int
    log_id: str
    key_folder: str

class InvalidConfigError(Exception):
    """Custom exception raised when no valid configuration is provided."""
    def __init__(self, message="No valid configuration given"):
        super().__init__(message)

def load_json_configuration(path, configuration_type):
    try:
        with open(path, 'r') as file:
            data: Configuration = json.load(file)
        must_have_items = list(configuration_type.__annotations__.keys())
        items = list(data.keys())
        if not all(c in items for c in must_have_items):
            raise InvalidConfigError 
        print("configuration loaded:", data)
        return data
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        raise InvalidConfigError 
    
configuration: Configuration = load_json_configuration(CONFIGURATION_FILE, Configuration)

class BC_Configuration(TypedDict):
    PRIVATE_KEY: str
    ACCOUNT_ADDRESS: str
    NODE_URL: str

bc_configuration: BC_Configuration = load_json_configuration(BC_CONFIGURATION_FILE, BC_Configuration)