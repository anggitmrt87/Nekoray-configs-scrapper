# scraper.py
import os
import re
import asyncio
import logging
import aiohttp
import base64
import json
from datetime import datetime
from config import API_ID, API_HASH, BOT_TOKEN, USER_SESSION_STRING, TELEGRAM_CHANNELS, APP_CONFIG
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import (
    FloodWaitError, 
    ChannelPrivateError,
    UsernameNotOccupiedError,
    UsernameNotOccupiedError
)

# 🎚️ Configure logging
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
        self.all_configs = []
        self.unique_configs = set()

    async def initialize_session(self):
        """🚀 Initialize aiohttp session"""
        self.session = aiohttp.ClientSession()

    async def __aenter__(self):
        await self.initialize_session()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """🧹 Cleanup resources"""
        if self.session:
            await self.session.close()
        if self.client:
            await self.client.disconnect()
        if self.bot:
            await self.bot.disconnect()

    async def get_country_from_ip(self, ip_address):
        """🌍 Get country from IP using ip-api.com"""
        if not ip_address or ip_address == 'UNKNOWN':
            return '🌐 UNKNOWN'
            
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]

        try:
            async with self.session.get(
                f'http://ip-api.com/json/{ip_address}?fields=status,message,country',
                timeout=5
            ) as resp:
                data = await resp.json()
                if data.get('status') == 'success':
                    country = data.get('country', '🌐 UNKNOWN')
                    self.ip_cache[ip_address] = country
                    return f'🇺🇳 {country}' if country != 'UNKNOWN' else '🌐 UNKNOWN'
                else:
                    logger.debug(f"IP API Error: {data.get('message')}")
        except Exception as e:
            logger.debug(f"Failed to get country for {ip_address}: {str(e)}")
        return '🌐 UNKNOWN'

    async def decode_base64_config(self, config):
        """🔓 Smart base64 decoding with padding handling"""
        try:
            if '://' in config:
                parts = config.split('://')
                if len(parts) == 2:
                    protocol, payload = parts
                    payload = payload.split('?')[0].split('#')[0]
                    padding = '=' * (-len(payload) % 4)
                    decoded = base64.b64decode(payload + padding).decode('utf-8')
                    return f"{protocol}://{decoded}"
            
            if len(config) > 20 and not any(c in config for c in [' ', '\n', '\t']):
                padding = '=' * (-len(config) % 4)
                decoded = base64.b64decode(config + padding).decode('utf-8')
                if any(proto in decoded.lower() for proto in ['vmess', 'vless', 'trojan']):
                    return decoded
        except Exception as e:
            logger.debug(f"Base64 decode failed: {str(e)}")
        return config

    async def extract_ip_from_config(self, config):
        """🔍 Extract IP/domain from config with validation"""
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
                host = host.strip('"\'').split('?')[0].split('/')[0].split(',')[0]
                if (re.match(r'^(\d+\.){3}\d+$', host) or 
                    ('.' in host and not host.startswith(('localhost', '127.')))):
                    return host
        return None

    async def extract_configs(self, text):
        """🧰 Extract configs from text with validation"""
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
                
                if len(config) < 10 or 'http' in config.lower():
                    continue
                
                decoded = await self.decode_base64_config(config)
                if decoded != config:
                    nested = await self.extract_configs(decoded)
                    configs.extend(nested)
                    continue
                
                if any(proto in config.lower() for proto in [
                    'vless', 'vmess', 'trojan', 'ss', 'tuic', 'hy2'
                ]):
                    configs.append(config)
        
        return list(set(configs))

    async def clear_existing_files(self):
        """🧹 Clean existing config files"""
        try:
            for root, dirs, files in os.walk(APP_CONFIG['config_folder']):
                for file in files:
                    if file.endswith('.txt') or file == 'README.md':
                        os.remove(os.path.join(root, file))
            logger.info("🧹 Cleaned existing config files")
        except Exception as e:
            logger.error(f"🧹 Clean failed: {str(e)}")

    async def save_configs(self, configs, channel_name):
        """💾 Save configs organized by protocol and country"""
        if not configs:
            return
    
        os.makedirs(APP_CONFIG['config_folder'], exist_ok=True)
        
        # Define config types WITHOUT emojis for dictionary keys
        config_types = {
            'vmess': {},
            'vless': {},
            'trojan': {},
            'ss': {},
            'tuic': {},
            'hy2': {}
        }
    
        for config in configs:
            if config in self.unique_configs:
                continue
            self.unique_configs.add(config)
            self.all_configs.append(config)
    
            config_lower = config.lower()
            
            # Determine config type (without emoji)
            if 'vmess://' in config_lower or '"v":"2"' in config_lower:
                config_type = 'vmess'
                emoji_type = '🟢 vmess'
            elif 'vless://' in config_lower:
                config_type = 'vless'
                emoji_type = '🔵 vless'
            elif 'trojan://' in config_lower:
                config_type = 'trojan'
                emoji_type = '🟣 trojan'
            elif 'ss://' in config_lower:
                config_type = 'ss'
                emoji_type = '🟠 ss'
            elif 'tuic://' in config_lower:
                config_type = 'tuic'
                emoji_type = '🟤 tuic'
            elif 'hy2://' in config_lower:
                config_type = 'hy2'
                emoji_type = '🟡 hy2'
            else:
                continue
    
            host = await self.extract_ip_from_config(config)
            country = await self.get_country_from_ip(host) if host else '🌐 UNKNOWN'
            
            if country not in config_types[config_type]:  # Now using the clean key
                config_types[config_type][country] = []
            config_types[config_type][country].append(config)
            
            self.country_stats[country] = self.country_stats.get(country, 0) + 1
            self.total_configs += 1
    
        for config_type, countries in config_types.items():
            # Get the emoji version for display
            emoji_type = {
                'vmess': '🟢 vmess',
                'vless': '🔵 vless',
                'trojan': '🟣 trojan',
                'ss': '🟠 ss',
                'tuic': '🟤 tuic',
                'hy2': '🟡 hy2'
            }.get(config_type, f'⚪ {config_type}')
            
            for country, configs in countries.items():
                if not configs:
                    continue
                    
                safe_country = re.sub(r'[^\w\s-]', '', country)
                country_folder = os.path.join(APP_CONFIG['config_folder'], safe_country)
                os.makedirs(country_folder, exist_ok=True)
                
                file_path = os.path.join(country_folder, f"{config_type}.txt")
                with open(file_path, 'a', encoding='utf-8') as f:
                    f.write(f"# {emoji_type} - {country}\n")
                    for config in configs:
                        f.write(f"{config}\n")
                    f.write("\n")

    async def create_all_configs_file(self):
        """📄 Create All_config.txt with all unique configs, better organized"""
        if not self.all_configs:
            logger.warning("⚠️ No configurations found to save in All_config.txt")
            return
    
        all_configs_path = os.path.join(APP_CONFIG['config_folder'], 'All_config.txt')
        
        try:
            with open(all_configs_path, 'w', encoding='utf-8') as f:
                f.write("# 🚀 All V2Ray Configurations\n")
                f.write(f"# ⏰ Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 🔢 Total Configs: {len(self.all_configs)}\n")
                f.write(f"# ✨ Unique Configs: {len(self.unique_configs)}\n")
                f.write(f"# 🌍 Countries: {len(self.country_stats)}\n\n")
                
                # Organize configs by protocol first
                protocol_groups = {
                    'vmess': [],
                    'vless': [],
                    'trojan': [],
                    'ss': [],
                    'tuic': [],
                    'hy2': []
                }
                
                # More accurate protocol detection
                for config in self.all_configs:
                    config_lower = config.lower()
                    if 'vmess://' in config_lower or ('"v":"2"' in config_lower and '"ps":' in config_lower):
                        protocol_groups['vmess'].append(config)
                    elif 'vless://' in config_lower and '@' in config_lower:
                        protocol_groups['vless'].append(config)
                    elif 'trojan://' in config_lower and '@' in config_lower:
                        protocol_groups['trojan'].append(config)
                    elif 'ss://' in config_lower and ('@' in config_lower or '?' in config_lower):
                        protocol_groups['ss'].append(config)
                    elif 'tuic://' in config_lower and '@' in config_lower:
                        protocol_groups['tuic'].append(config)
                    elif 'hy2://' in config_lower and '@' in config_lower:
                        protocol_groups['hy2'].append(config)
                
                # Write organized configs
                protocols_order = [
                    ('🟢 vmess', 'vmess'),
                    ('🔵 vless', 'vless'),
                    ('🟣 trojan', 'trojan'),
                    ('🟠 ss', 'ss'),
                    ('🟤 tuic', 'tuic'),
                    ('🟡 hy2', 'hy2')
                ]
                
                for emoji_proto, proto in protocols_order:
                    if protocol_groups[proto]:
                        f.write(f"\n=== {emoji_proto.upper()} Configurations ({len(protocol_groups[proto])}) ===\n\n")
                        # Sort configs alphabetically for better organization
                        for config in sorted(protocol_groups[proto]):
                            f.write(f"{config}\n")
            
            logger.info(f"📄 Created All_config.txt with {len(self.unique_configs)} unique configs")
        except Exception as e:
            logger.error(f"❌ Failed to create All_config.txt: {str(e)}")

    async def generate_readme(self):
        """📝 Generate README.md with statistics"""
        readme_path = os.path.join(APP_CONFIG['config_folder'], 'README.md')
        
        country_protocols = {}
        for root, dirs, files in os.walk(APP_CONFIG['config_folder']):
            if root == APP_CONFIG['config_folder']:
                continue
            
            country = os.path.basename(root)
            protocols = set()
            
            for file in files:
                if file.endswith('.txt'):
                    protocol = file.split('.')[0]
                    emoji = {
                        'vmess': '🟢',
                        'vless': '🔵',
                        'trojan': '🟣',
                        'ss': '🟠',
                        'tuic': '🟤',
                        'hy2': '🟡'
                    }.get(protocol, '⚪')
                    protocols.add(f"{emoji} {protocol}")
            
            if protocols:
                country_protocols[country] = sorted(protocols)
        
        sorted_countries = sorted(country_protocols.items(), key=lambda x: x[0])
        
        readme_content = f"""# 🌐 V2Ray Configuration Collection

## 📦 Available Configurations

| Country       | Protocols               |
|---------------|-------------------------|
"""
        for country, protocols in sorted_countries:
            protocol_str = ' '.join(protocols)
            readme_content += f"| {country.ljust(13)} | {protocol_str.ljust(40)} |\n"

        readme_content += f"""
## 📊 Statistics

- 🔢 Total Configurations: {self.total_configs}
- ✨ Unique Configurations: {len(self.unique_configs)}
- 🌍 Countries Available: {len(country_protocols)}
- ⏰ Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

*Automatically generated*
"""

        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        logger.info(f"📝 README.md generated at {readme_path}")

    async def join_channel(self, channel):
        """🤖 Join channel with flood control"""
        try:
            entity = await self.client.get_entity(channel)
            if not await self.client.is_participant(entity):
                await self.client.join_channel(entity)
                logger.info(f"✅ Joined @{channel}")
                return True
        except FloodWaitError as e:
            logger.warning(f"⏳ Flood wait: {e.seconds} seconds")
            await asyncio.sleep(e.seconds)
        except Exception as e:
            logger.error(f"❌ Join failed @{channel}: {str(e)}")
        return False

    async def scrape_channel(self, channel):
        """🔍 Scrape a Telegram channel with comprehensive error handling"""
        try:
            # Verify channel exists
            try:
                entity = await self.client.get_entity(channel)
                # Get a display name that works for both channels and users
                display_name = getattr(entity, 'title', None) or getattr(entity, 'username', None) or 'private'
                logger.info(f"🔍 Scraping: {display_name}")
            except ValueError as e:
                if "Cannot find any entity" in str(e) or "No user has" in str(e):
                    logger.error(f"❌ Channel/User {channel} not found")
                    return 0
                raise
            except UsernameNotOccupiedError:
                logger.error(f"❌ Channel username not found: {channel}")
                return 0
            except ChannelPrivateError:
                logger.error(f"🔒 Channel is private: {channel}")
                return 0
            except Exception as e:
                logger.error(f"⚠️ Error accessing {channel}: {str(e)}")
                return 0
    
            # Auto-join if needed
            if APP_CONFIG['auto_join']:
                try:
                    if not await self.client.is_participant(entity):
                        await self.client.join_channel(entity)
                        logger.info(f"🤖 Joined: {display_name}")
                        await asyncio.sleep(5)
                except FloodWaitError as e:
                    logger.warning(f"⏳ Flood wait: {e.seconds}s")
                    await asyncio.sleep(e.seconds)
                    return await self.scrape_channel(channel)
                except Exception as e:
                    logger.error(f"❌ Join failed: {str(e)}")
                    if "USER_ALREADY_PARTICIPANT" not in str(e):
                        return 0
    
            logger.info(f"📡 Starting scrape (last msg: {max(self.processed_messages, default=0)})")
            configs = []
            message_count = 0
            config_count = 0
    
            try:
                async for message in self.client.iter_messages(
                    entity,
                    limit=APP_CONFIG['limit_messages'],
                    wait_time=APP_CONFIG['request_delay'],
                    offset_id=max(self.processed_messages, default=0)
                ):
                    message_count += 1
                    
                    if message.id in self.processed_messages or not message.text:
                        continue
    
                    try:
                        found_configs = await self.extract_configs(message.text)
                        if found_configs:
                            configs.extend(found_configs)
                            config_count += len(found_configs)
                            self.processed_messages.add(message.id)
                            logger.debug(f"🔧 Found {len(found_configs)} configs in msg {message.id}")
    
                        if len(configs) >= 50:
                            await self.save_configs(configs, display_name)
                            configs = []
                            logger.info(f"💾 Saved batch - Total: {config_count}")
    
                    except Exception as e:
                        logger.error(f"⚠️ Message error: {str(e)}")
                        continue
    
                    await asyncio.sleep(APP_CONFIG['request_delay'])
    
            except FloodWaitError as e:
                logger.warning(f"⏳ Flood wait: {e.seconds}s")
                await asyncio.sleep(e.seconds)
                return await self.scrape_channel(channel)
    
            if configs:
                await self.save_configs(configs, display_name)
    
            logger.info(f"✅ Finished: {message_count} msgs, {config_count} configs")
            return config_count
    
        except Exception as e:
            logger.error(f"💥 Fatal error in scrape_channel: {str(e)}", exc_info=True)
            return 0

    async def run(self):
        """🚀 Main execution flow"""
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
                logger.info("🤖 Clients initialized")

                await self.clear_existing_files()
                
                successful_channels = []
                
                for channel in TELEGRAM_CHANNELS:
                    count = await self.scrape_channel(channel)
                    if count > 0:
                        successful_channels.append(f"@{channel}")
                
                await self.create_all_configs_file()
                await self.generate_readme()
                
                report = [
                    "📊 V2Ray Scraper Report",
                    f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "",
                    f"🔢 Total Configs: {self.total_configs}",
                    f"✨ Unique Configs: {len(self.unique_configs)}",
                    f"📢 Channels: {len(successful_channels)}/{len(TELEGRAM_CHANNELS)}",
                    f"🌍 Countries: {len(self.country_stats)}",
                    "",
                    "🏆 Top Countries:"
                ]
                
                for country, count in sorted(
                    self.country_stats.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]:
                    report.append(f"  - {country}: {count} configs")
                
                if successful_channels:
                    report.extend(["", "🔥 Top Channels:"])
                    report.extend(f"  - {ch}" for ch in successful_channels[:5])
                
                report.extend([
                    "",
                    "📁 Output Files:",
                    f"  - All_config.txt ({len(self.unique_configs)} configs)",
                    f"  - Organized by country/protocol",
                    f"  - README.md generated"
                ])
                
                await self.bot.send_message(
                    APP_CONFIG['admin_id'],
                    "\n".join(report)
                )
                
                logger.info(f"🎉 Scraping completed! Found {self.total_configs} configs")
                
            except Exception as e:
                logger.error(f"💥 Fatal error: {str(e)}", exc_info=True)
                await self.bot.send_message(
                    APP_CONFIG['admin_id'],
                    f"💥 Scraper crashed: {str(e)}"
                )
