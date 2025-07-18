# main.py
import asyncio
import logging
from scraper import V2RayScraper

async def main():
    """🚀 Entry point for the V2Ray scraper"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('v2ray_scraper.log'),
            logging.StreamHandler()
        ]
    )
    
    try:
        async with V2RayScraper() as scraper:
            await scraper.run()
    except Exception as e:
        logging.error(f"💥 Main error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
