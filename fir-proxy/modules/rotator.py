# modules/rotator.py

import threading
from collections import defaultdict

class ProxyRotator:
    """代理轮换器."""
    def __init__(self):
        self.all_proxies = []
        self.proxies_by_country = defaultdict(list)
        self.indices = defaultdict(lambda: -1)
        self.current_proxy = None
        self.lock = threading.Lock()

    def clear(self):
        """清空所有代理."""
        with self.lock:
            self.all_proxies = []
            self.proxies_by_country.clear()
            self.indices.clear()
            self.current_proxy = None
            
    def add_proxy(self, proxy_info: dict):
        """添加一个代理."""
        with self.lock:
            proxy_address = proxy_info.get('proxy')
            if any(p.get('proxy') == proxy_address for p in self.all_proxies):
                return 

            self.all_proxies.append(proxy_info)
            country = proxy_info.get('location', 'Unknown')
            self.proxies_by_country[country].append(proxy_info)

    def remove_proxy(self, proxy_address: str):
        """通过地址删除代理."""
        with self.lock:
            proxy_to_remove = None
            for p_info in self.all_proxies:
                if p_info.get('proxy') == proxy_address:
                    proxy_to_remove = p_info
                    break
            
            if proxy_to_remove:
                self.all_proxies.remove(proxy_to_remove)
                
                country = proxy_to_remove.get('location', 'Unknown')
                if country in self.proxies_by_country:
                    try:
                        self.proxies_by_country[country].remove(proxy_to_remove)
                        if not self.proxies_by_country[country]:
                            del self.proxies_by_country[country]
                    except ValueError:
                        pass
                
                if self.current_proxy == proxy_to_remove:
                    self.current_proxy = None
                return True
            return False

    def get_working_proxies_count(self) -> int:
        """获取可用代理总数."""
        with self.lock:
            return len(self.all_proxies)

    def get_available_regions_with_counts(self, premium_only=False) -> dict:
        """获取各区域的代理数量."""
        with self.lock:
            # 统一逻辑
            counts = {}
            for region, proxies in self.proxies_by_country.items():
                if not proxies:
                    continue
                
                if premium_only:
                    # 统计优质代理
                    count = sum(1 for p in proxies if p.get('latency', float('inf')) * 1000 < 2000)
                    if count > 0:
                        counts[region] = count
                else:
                    counts[region] = len(proxies)
            return counts


    def get_next_proxy(self, region="All", premium_only=False):
        """获取下一个代理."""
        with self.lock:
            source_list = []
            region_key = region
            
            if region == "All":
                source_list = self.all_proxies
            elif region in self.proxies_by_country:
                source_list = self.proxies_by_country[region]
            else: 
                # 若区域不存在, 则从全部代理中选
                source_list = self.all_proxies
                region_key = "All"

            # 筛选列表
            if premium_only:
                target_list = [
                    p for p in source_list 
                    if p.get('latency', float('inf')) * 1000 < 2000
                ]
            else:
                target_list = source_list

            if not target_list:
                self.current_proxy = None
                return None

            # 用独立的键保存索引
            index_key = f"{region_key}_{'premium' if premium_only else 'all'}"
            
            current_idx = self.indices.get(index_key, -1)
            next_idx = (current_idx + 1) % len(target_list)
            self.indices[index_key] = next_idx
            
            self.current_proxy = target_list[next_idx]
            return self.current_proxy

    def get_current_proxy(self):
        """获取当前代理."""
        with self.lock:
            return self.current_proxy

    def set_current_proxy_by_address(self, proxy_address: str):
        """通过地址设置当前代理."""
        with self.lock:
            for p_info in self.all_proxies:
                if p_info.get('proxy') == proxy_address:
                    self.current_proxy = p_info
                    return p_info
            return None