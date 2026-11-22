
from scapy.all import get_if_list

from tp1.utils.config import logger


def hello_world() -> str:
    """Return a simple greeting for compatibility with the template tests."""
    return "Hello World!"


def choose_interface() -> str:
    """Ask the user to choose a network interface."""
    try:
        interfaces = get_if_list()
    except Exception as exc:
        logger.error("Impossible de récupérer les interfaces : %s", exc)
        return ""

    if not interfaces:
        logger.warning("Aucune interface réseau disponible.")
        return ""

    print("\nInterfaces réseau disponibles :")

    for index, interface in enumerate(interfaces, start=1):
        print(f"{index}. {interface}")

    while True:
        choice = input(
            "Choisissez une interface (numéro, ou Entrée pour annuler) : "
        ).strip()

        if not choice:
            return ""

        if choice.isdigit():
            index = int(choice)

            if 1 <= index <= len(interfaces):
                selected = interfaces[index - 1]
                logger.info("Interface sélectionnée : %s", selected)
                return selected

        print("Choix invalide. Saisissez un numéro de la liste.")
