import os
import re
import asyncio
import logging
import aiohttp
import base64
from datetime import datetime
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError, ChannelPrivateError
from config import API_ID, API_HASH, BOT_TOKEN, USER_SESSION_STRING, TELEGRAM_CHANNELS, APP_CONFIG

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('v2ray_scraper.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class V2RayScraper:
    def __init__(self):
        self.client = None
        self.bot = None
        self.processed_messages = set()
        self.ip_cache = {}
        self.session = None
        self.country_stats = {}
        self.total_configs = 0
        self.all_configs = []  # Store all configs for All_config.txt
        self.unique_configs = set()  # For duplicate detection

    async def initialize_session(self):
        self.session = aiohttp.ClientSession()

    async def __aenter__(self):
        await self.initialize_session()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
        if self.client:
            await self.client.disconnect()
        if self.bot:
            await self.bot.disconnect()

    async def get_country_from_ip(self, ip_address):
        """Get full country name from IP using ip-api.com"""
        if not ip_address or ip_address == 'UNKNOWN':
            return 'UNKNOWN'
            
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]

        try:
            async with self.session.get(
                f'http://ip-api.com/json/{ip_address}?fields=status,message,country',
                timeout=5
            ) as resp:
                data = await resp.json()
                if data.get('status') == 'success':
                    country = data.get('country', 'UNKNOWN')
                    self.ip_cache[ip_address] = country
                    return country
                else:
                    logger.debug(f"IP API Error: {data.get('message')}")
        except Exception as e:
            logger.debug(f"Failed to get country for {ip_address}: {str(e)}")
        return 'UNKNOWN'

    async def decode_base64_config(self, config):
        """Smart base64 decoding with padding handling"""
        try:
            # Handle vmess:// style configs
            if '://' in config:
                parts = config.split('://')
                if len(parts) == 2:
                    protocol, payload = parts
                    # Add padding if needed
                    payload = payload.split('?')[0].split('#')[0]
                    padding = '=' * (-len(payload) % 4)
                    decoded = base64.b64decode(payload + padding).decode('utf-8')
                    return f"{protocol}://{decoded}"
            
            # Handle standalone base64
            if len(config) > 20 and not any(c in config for c in [' ', '\n', '\t']):
                padding = '=' * (-len(config) % 4)
                decoded = base64.b64decode(config + padding).decode('utf-8')
                if any(proto in decoded.lower() for proto in ['vmess', 'vless', 'trojan']):
                    return decoded
        except Exception as e:
            logger.debug(f"Base64 decode failed: {str(e)}")
        return config

    async def extract_ip_from_config(self, config):
        """Improved IP/domain extraction with validation"""
        patterns = [
            r'@([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
            r'host\s*[=:]\s*["\']?([^"\'\s]+)',
            r'server\s*[=:]\s*["\']?([^"\'\s]+)',
            r'address\s*[=:]\s*["\']?([^"\'\s]+)',
            r'(?:vless|vmess|trojan|ss|tuic|hy2)://[^@]+@([^:/]+)',
            r'\"host\"\s*:\s*\"([^\"]+)\"'
        ]

        for pattern in patterns:
            match = re.search(pattern, config, re.IGNORECASE)
            if match:
                host = match.group(1)
                # Clean and validate
                host = host.strip('"\'').split('?')[0].split('/')[0].split(',')[0]
                if (re.match(r'^(\d+\.){3}\d+$', host) or 
                    ('.' in host and not host.startswith(('localhost', '127.')))):
                    return host
        return None

    async def extract_configs(self, text):
        """Comprehensive config extraction with validation"""
        patterns = [
            r'(vless|vmess|trojan|ss|tuic|hy2)://[^\s"\'\{\}]+',
            r'\{\s*"v"\s*:\s*"2".*?\}',
            r'eyJ[A-Za-z0-9+/]+={0,2}',
            r'(?:[a-z0-9]+\.)+[a-z]{2,}(?::\d+)?'
        ]

        configs = []
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                config = match.group(0).strip()
                
                # Skip invalid
                if len(config) < 10 or 'http' in config.lower():
                    continue
                
                # Decode and recursively extract
                decoded = await self.decode_base64_config(config)
                if decoded != config:
                    nested = await self.extract_configs(decoded)
                    configs.extend(nested)
                    continue
                
                # Validate protocol
                if any(proto in config.lower() for proto in [
                    'vless', 'vmess', 'trojan', 'ss', 'tuic', 'hy2'
                ]):
                    configs.append(config)
        
        return list(set(configs))

    async def clear_existing_files(self):
        """Clean existing config files including All_config.txt"""
        try:
            for root, dirs, files in os.walk(APP_CONFIG['config_folder']):
                for file in files:
                    if file.endswith('.txt') or file == 'README.md':
                        os.remove(os.path.join(root, file))
            logger.info("Cleaned existing config files")
        except Exception as e:
            logger.error(f"Clean failed: {str(e)}")

    async def save_configs(self, configs, channel_name):
        """Save configs organized by protocol and country"""
        if not configs:
            return

        os.makedirs(APP_CONFIG['config_folder'], exist_ok=True)
        
        config_types = {
            'vmess': {},
            'vless': {},
            'trojan': {},
            'ss': {},
            'tuic': {},
            'hy2': {}
        }

        for config in configs:
            # Skip duplicates
            if config in self.unique_configs:
                continue
            self.unique_configs.add(config)
            self.all_configs.append(config)

            config_lower = config.lower()
            if 'vmess://' in config_lower or '"v":"2"' in config_lower:
                config_type = 'vmess'
            elif 'vless://' in config_lower:
                config_type = 'vless'
            elif 'trojan://' in config_lower:
                config_type = 'trojan'
            elif 'ss://' in config_lower:
                config_type = 'ss'
            elif 'tuic://' in config_lower:
                config_type = 'tuic'
            elif 'hy2://' in config_lower:
                config_type = 'hy2'
            else:
                continue

            host = await self.extract_ip_from_config(config)
            country = await self.get_country_from_ip(host) if host else 'UNKNOWN'
            
            if country not in config_types[config_type]:
                config_types[config_type][country] = []
            config_types[config_type][country].append(config)
            
            # Update stats
            self.country_stats[country] = self.country_stats.get(country, 0) + 1
            self.total_configs += 1

        # Save to organized folders
        for config_type, countries in config_types.items():
            for country, configs in countries.items():
                if not configs:
                    continue
                    
                # Clean country name for filesystem
                safe_country = re.sub(r'[\\/*?:"<>|]', '', country)
                country_folder = os.path.join(APP_CONFIG['config_folder'], safe_country)
                os.makedirs(country_folder, exist_ok=True)
                
                file_path = os.path.join(country_folder, f"{config_type}.txt")
                with open(file_path, 'a', encoding='utf-8') as f:
                    for config in configs:
                        f.write(f"{config}\n")

    async def create_all_configs_file(self):
        """Create All_config.txt containing all unique configurations"""
        if not self.all_configs:
            logger.warning("No configurations found to save in All_config.txt")
            return

        all_configs_path = os.path.join(APP_CONFIG['config_folder'], 'All_config.txt')
        
        try:
            with open(all_configs_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write("# All V2Ray Configurations\n")
                f.write(f"# Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total Unique Configs: {len(self.unique_configs)}\n")
                f.write(f"# Countries: {len(self.country_stats)}\n\n")
                
                # Write configs grouped by protocol
                protocols = ['vmess', 'vless', 'trojan', 'ss', 'tuic', 'hy2']
                for proto in protocols:
                    proto_configs = [c for c in self.all_configs if proto in c.lower()]
                    if proto_configs:
                        f.write(f"\n=== {proto.upper()} Configurations ===\n\n")
                        for config in proto_configs:
                            f.write(f"{config}\n")
            
            logger.info(f"Created All_config.txt with {len(self.unique_configs)} unique configs")
        except Exception as e:
            logger.error(f"Failed to create All_config.txt: {str(e)}")

    async def generate_readme(self):
        """Generate README.md file with statistics and protocol availability"""
        readme_path = os.path.join(APP_CONFIG['config_folder'], 'README.md')
        
        # Collect protocol availability by country
        country_protocols = {}
        for root, dirs, files in os.walk(APP_CONFIG['config_folder']):
            if root == APP_CONFIG['config_folder']:
                continue  # Skip the root directory
            
            country = os.path.basename(root)
            protocols = set()
            
            for file in files:
                if file.endswith('.txt'):
                    protocol = file.split('.')[0]
                    protocols.add(protocol)
            
            if protocols:
                country_protocols[country] = sorted(protocols)
        
        # Sort countries alphabetically
        sorted_countries = sorted(country_protocols.items(), key=lambda x: x[0])
        
        # Generate the markdown content
        readme_content = f"""# Nekoray Configuration

## 🌍 Available Configurations

| Country/City       | Available Protocols               |
|--------------------|-----------------------------------|
"""
        # Add countries to the table
        for country, protocols in sorted_countries:
            protocol_str = ', '.join(protocols)
            readme_content += f"| {country.ljust(18)} | {protocol_str.ljust(30)} |\n"

        readme_content += f"""
## 📊 Statistics

- Total Configurations: {self.total_configs}
- Unique Configurations: {len(self.unique_configs)}
- Countries Available: {len(country_protocols)}
- Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

*Automatically generated by NekoDev™*
"""
        # Write to README.md
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        logger.info(f"README.md generated at {readme_path}")

    async def join_channel(self, channel):
        """Join channel with flood control"""
        try:
            entity = await self.client.get_entity(channel)
            if not await self.client.is_participant(entity):
                await self.client.join_channel(channel)
                logger.info(f"Joined @{channel}")
                return True
        except FloodWaitError as e:
            logger.warning(f"Flood wait: {e.seconds} seconds")
            await asyncio.sleep(e.seconds)
        except Exception as e:
            logger.error(f"Join failed @{channel}: {str(e)}")
        return False

    async def scrape_channel(self, channel):
        """Scrape channel with rate limiting"""
        try:
            if APP_CONFIG['auto_join']:
                await self.join_channel(channel)

            logger.info(f"Scraping @{channel}...")
            configs = []
            
            async for message in self.client.iter_messages(
                channel,
                limit=APP_CONFIG['limit_messages'],
                wait_time=APP_CONFIG['request_delay']
            ):
                if message.id in self.processed_messages or not message.text:
                    continue
                    
                found = await self.extract_configs(message.text)
                if found:
                    configs.extend(found)
                    self.processed_messages.add(message.id)
                
                # Batch save every 50 configs
                if len(configs) >= 50:
                    await self.save_configs(configs, channel)
                    configs = []
                
                await asyncio.sleep(APP_CONFIG['request_delay'])
            
            # Save remaining configs
            if configs:
                await self.save_configs(configs, channel)
                return len(configs)
                
        except FloodWaitError as e:
            logger.warning(f"Flood wait {e.seconds}s, retrying...")
            await asyncio.sleep(e.seconds)
            return await self.scrape_channel(channel)
        except ChannelPrivateError:
            logger.error(f"Private channel @{channel}")
        except Exception as e:
            logger.error(f"Scrape error @{channel}: {str(e)}")
        
        return 0

    async def run(self):
        """Main execution flow"""
        async with self:
            self.client = TelegramClient(
                StringSession(USER_SESSION_STRING),
                API_ID,
                API_HASH
            )
            self.bot = TelegramClient('bot', API_ID, API_HASH)
            
            try:
                await self.client.start()
                await self.bot.start(bot_token=BOT_TOKEN)
                logger.info("Clients initialized")

                await self.clear_existing_files()
                
                successful_channels = []
                
                for channel in TELEGRAM_CHANNELS:
                    count = await self.scrape_channel(channel)
                    if count > 0:
                        successful_channels.append(channel)
                
                # Create All_config.txt after scraping all channels
                await self.create_all_configs_file()
                
                # Generate README.md
                await self.generate_readme()
                
                # Generate detailed report
                report = [
                    "🌐 V2Ray Scraper Report",
                    f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "",
                    f"📦 Total Configs: {self.total_configs}",
                    f"🔑 Unique Configs: {len(self.unique_configs)}",
                    f"📢 Channels: {len(successful_channels)}/{len(TELEGRAM_CHANNELS)}",
                    f"🌍 Countries: {len(self.country_stats)}",
                    "",
                    "🏆 Top Countries:"
                ]
                
                # Sort countries by config count
                sorted_countries = sorted(
                    self.country_stats.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]  # Show top 10 countries
                
                for country, count in sorted_countries:
                    report.append(f"  - {country}: {count} configs")
                
                # Add top channels
                if successful_channels:
                    report.extend(["", "🔥 Top Channels:"])
                    report.extend(f"  - @{ch}" for ch in successful_channels[:5])
                
                report.extend([
                    "",
                    "📁 Config Files:",
                    f"  - All_config.txt ({len(self.unique_configs)} configs)",
                    f"  - Organized by country/protocol",
                    f"  - README.md generated"
                ])
                
                await self.bot.send_message(
                    APP_CONFIG['admin_id'],
                    "\n".join(report)
                )
                
                logger.info(f"Scraping completed. Found {self.total_configs} configs ({len(self.unique_configs)} unique)")
                
            except Exception as e:
                logger.error(f"Fatal error: {str(e)}", exc_info=True)
                await self.bot.send_message(
                    APP_CONFIG['admin_id'],
                    f"⚠️ Scraper crashed: {str(e)}"
                )

if __name__ == "__main__":
    async def main():
        async with V2RayScraper() as scraper:
            await scraper.run()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    finally:
        loop.close()
