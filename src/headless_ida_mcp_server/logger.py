
import logging
#### LOGGING ####
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('headless_ida_mcp_server')
logger.setLevel(logging.DEBUG)
logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.ERROR)
