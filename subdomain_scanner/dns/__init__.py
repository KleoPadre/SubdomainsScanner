"""
Модуль для работы с DNS-методами обнаружения поддоменов
"""

from .zone_transfer import try_zone_transfer
from .brute_force import find_subdomains, check_subdomain, load_wordlist
