from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK

apk, _, _ = AnalyzeAPK("calculator.apk")

print("Package name:", apk.get_package())
print("Permissions:", apk.get_permissions())

