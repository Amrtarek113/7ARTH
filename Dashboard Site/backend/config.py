import os

class Config:
    DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
    PORT = int(os.getenv('PORT', 5000))
    HOST = os.getenv('HOST', '0.0.0.0')
    UNSW_DATA_PATH = os.getenv('UNSW_DATA_PATH', 'UNSW_NB15_training-set.csv')

def get_config():
    return Config