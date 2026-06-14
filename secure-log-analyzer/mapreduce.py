from collections import defaultdict
from multiprocessing import Pool, cpu_count
import re
from typing import List, Tuple, Dict, Any

def split_file(lines: List[str], chunks: int = None) -> List[List[str]]:
    """Split file into chunks for parallel processing"""
    if chunks is None:
        chunks = max(1, cpu_count())
    
    size = max(1, len(lines) // chunks)
    return [lines[i:i+size] for i in range(0, len(lines), size)]

def mapper(chunk: List[str]) -> List[Tuple]:
    """Enhanced map function for processing log chunks"""
    result = []
    
    for line in chunk:
        line_lower = line.lower()
        
        # 1. Extract HTTP status codes
        match = re.search(r'" (\d{3}) ', line)
        if match:
            code = match.group(1)
            result.append((f"status_code_{code}", 1))
        
        # 2. Extract hour from timestamp
        time_match = re.search(r'\[(\d{2})/[A-Za-z]+/\d{4}:(\d{2}):(\d{2}):(\d{2})', line)
        if time_match:
            hour = time_match.group(2)
            minute = time_match.group(3)
            result.append((f"hour_{hour}", 1))
            result.append((f"minute_{hour}_{minute}", 1))
        
        # 3. Extract error patterns
        error_patterns = {
            'ERROR': 1, 'FATAL': 2, 'CRITICAL': 3, 
            'Exception': 1, 'Timeout': 1, 'Connection refused': 1,
            'Database error': 1, 'NullPointer': 1, 'StackOverflow': 1
        }
        for pattern, weight in error_patterns.items():
            if pattern.lower() in line_lower:
                result.append((f"error_{pattern}", weight))
        
        # 4. Extract IP addresses
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip = ip_match.group(1)
            result.append((f"ip_{ip}", 1))
            
            # Classify IP ranges
            ip_first = int(ip.split('.')[0])
            if ip_first == 192:
                result.append(("ip_class_private", 1))
            elif ip_first == 10:
                result.append(("ip_class_private", 1))
            elif ip_first == 172:
                result.append(("ip_class_private", 1))
            else:
                result.append(("ip_class_public", 1))
        
        # 5. Extract request methods
        method_match = re.search(r'"([A-Z]+) ', line)
        if method_match:
            method = method_match.group(1)
            result.append((f"method_{method}", 1))
        
        # 6. Extract response size
        size_match = re.search(r'" \d{3} (\d+)', line)
        if size_match:
            size = int(size_match.group(1))
            result.append(("total_response_size", size))
            if size < 1024:
                result.append(("response_size_small", 1))
            elif size < 10240:
                result.append(("response_size_medium", 1))
            else:
                result.append(("response_size_large", 1))
        
        # 7. Extract user agents
        ua_match = re.search(r'"([^"]+)"$', line)
        if ua_match:
            ua = ua_match.group(1)
            if 'Chrome' in ua:
                result.append(("browser_chrome", 1))
            elif 'Firefox' in ua:
                result.append(("browser_firefox", 1))
            elif 'Safari' in ua:
                result.append(("browser_safari", 1))
            elif 'Edge' in ua:
                result.append(("browser_edge", 1))
            else:
                result.append(("browser_other", 1))
        
        # 8. Extract endpoints
        endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) ([^?]+)', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            result.append((f"endpoint_{endpoint}", 1))
            
            # Classify endpoint types
            if '/api/' in endpoint:
                result.append(("endpoint_type_api", 1))
            elif '/static/' in endpoint:
                result.append(("endpoint_type_static", 1))
            elif '/admin' in endpoint:
                result.append(("endpoint_type_admin", 1))
            else:
                result.append(("endpoint_type_other", 1))
        
        # 9. Response time analysis
        time_match = re.search(r'response_time=(\d+)', line)
        if time_match:
            resp_time = int(time_match.group(1))
            result.append(("total_response_time_ms", resp_time))
            if resp_time < 100:
                result.append(("response_time_fast", 1))
            elif resp_time < 500:
                result.append(("response_time_normal", 1))
            elif resp_time < 1000:
                result.append(("response_time_slow", 1))
            else:
                result.append(("response_time_very_slow", 1))
    
    return result

def shuffle(mapped_data: List[List[Tuple]]) -> Dict[str, List]:
    """Shuffle phase: group by key"""
    grouped = defaultdict(list)
    
    for sublist in mapped_data:
        for key, value in sublist:
            grouped[key].append(value)
    
    return grouped

def reduce(grouped: Dict[str, List]) -> Dict[str, Any]:
    """Enhanced reduce phase with different aggregation types"""
    reduced = {}
    
    for key, values in grouped.items():
        if key == 'total_response_size':
            reduced[key] = sum(values)
        elif key == 'total_response_time_ms':
            reduced[key] = sum(values)
            reduced['avg_response_time_ms'] = sum(values) // len(values) if values else 0
            reduced['max_response_time_ms'] = max(values) if values else 0
            reduced['min_response_time_ms'] = min(values) if values else 0
        else:
            reduced[key] = sum(values)
    
    return reduced

def analyze_performance_metrics(result: Dict[str, int]) -> Dict[str, Any]:
    """Calculate performance metrics from results"""
    metrics = {}
    
    # Calculate request counts
    status_codes = {k.split('_')[2]: v for k, v in result.items() if k.startswith('status_code_')}
    metrics['total_requests'] = sum(status_codes.values())
    metrics['status_codes'] = status_codes
    
    # Calculate error rate
    error_keys = [k for k in result.keys() if k.startswith('error_')]
    metrics['total_errors'] = sum(result.get(k, 0) for k in error_keys)
    metrics['error_rate'] = (metrics['total_errors'] / metrics['total_requests'] * 100) if metrics['total_requests'] > 0 else 0
    
    # Get top errors
    errors = {k.replace('error_', ''): v for k, v in result.items() if k.startswith('error_')}
    metrics['top_errors'] = dict(sorted(errors.items(), key=lambda x: x[1], reverse=True)[:5])
    
    # Get top endpoints
    endpoints = {k.replace('endpoint_', ''): v for k, v in result.items() if k.startswith('endpoint_') and not k.startswith('endpoint_type_')}
    metrics['top_endpoints'] = dict(sorted(endpoints.items(), key=lambda x: x[1], reverse=True)[:10])
    
    # Get top IPs
    ips = {k.replace('ip_', ''): v for k, v in result.items() if k.startswith('ip_') and not k.startswith('ip_class_')}
    metrics['top_ips'] = dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])
    
    # Traffic by hour
    hours = {k.replace('hour_', ''): v for k, v in result.items() if k.startswith('hour_')}
    if hours:
        metrics['peak_hour'] = max(hours, key=hours.get)
        metrics['peak_hour_traffic'] = hours[metrics['peak_hour']]
        metrics['hourly_traffic'] = hours
    
    # Request methods
    methods = {k.replace('method_', ''): v for k, v in result.items() if k.startswith('method_')}
    metrics['request_methods'] = methods
    
    # Response time analysis
    if 'avg_response_time_ms' in result:
        metrics['avg_response_time'] = result['avg_response_time_ms']
        metrics['max_response_time'] = result['max_response_time_ms']
        metrics['min_response_time'] = result['min_response_time_ms']
    
    # Browser distribution
    browsers = {k.replace('browser_', ''): v for k, v in result.items() if k.startswith('browser_')}
    metrics['browser_distribution'] = browsers
    
    return metrics

def generate_insights(metrics: Dict[str, Any]) -> List[str]:
    """Generate human-readable insights from metrics"""
    insights = []
    
    # Performance insights
    if metrics.get('total_requests', 0) > 0:
        insights.append(f"📊 Total requests analyzed: {metrics['total_requests']:,}")
    
    if metrics.get('error_rate', 0) > 5:
        insights.append(f"⚠️ High error rate detected: {metrics['error_rate']:.2f}%")
    elif metrics.get('error_rate', 0) > 0:
        insights.append(f"ℹ️ Error rate: {metrics['error_rate']:.2f}%")
    
    if metrics.get('top_errors'):
        insights.append(f"🔥 Most common error: {list(metrics['top_errors'].keys())[0]} ({list(metrics['top_errors'].values())[0]} times)")
    
    if metrics.get('peak_hour'):
        insights.append(f"⏰ Peak traffic hour: {metrics['peak_hour']}:00 ({metrics['peak_hour_traffic']} requests)")
    
    if metrics.get('avg_response_time', 0) > 500:
        insights.append(f"🐌 Slow average response time: {metrics['avg_response_time']}ms")
    elif metrics.get('avg_response_time', 0) > 0:
        insights.append(f"⚡ Average response time: {metrics['avg_response_time']}ms")
    
    if metrics.get('top_endpoints'):
        top_endpoint = list(metrics['top_endpoints'].keys())[0]
        insights.append(f"🎯 Most requested endpoint: {top_endpoint}")
    
    if metrics.get('browser_distribution'):
        top_browser = max(metrics['browser_distribution'], key=metrics['browser_distribution'].get)
        insights.append(f"🌐 Most popular browser: {top_browser.capitalize()}")
    
    # Security insights
    admin_endpoints = [k for k in metrics.get('top_endpoints', {}).keys() if 'admin' in k]
    if admin_endpoints:
        insights.append(f"🔒 Admin endpoints accessed: {', '.join(admin_endpoints[:3])}")
    
    return insights

def run_mapreduce(lines: List[str]) -> Dict[str, Any]:
    """Main MapReduce execution function with enhanced analytics"""
    
    if not lines:
        return {
            'message': 'No data to analyze',
            'metrics': {},
            'insights': []
        }
    
    print(f"📊 Processing {len(lines)} lines with {cpu_count()} CPU cores...")
    
    # Split data for parallel processing
    chunks = split_file(lines)
    
    # Parallel mapping
    with Pool(processes=cpu_count()) as pool:
        mapped = pool.map(mapper, chunks)
    
    # Shuffle and reduce
    grouped = shuffle(mapped)
    reduced = reduce(grouped)
    
    # Calculate performance metrics
    metrics = analyze_performance_metrics(reduced)
    
    # Generate insights
    insights = generate_insights(metrics)
    
    # Prepare final result
    result = {
        'summary': {
            'total_lines_processed': len(lines),
            'parallel_chunks': len(chunks),
            'cpu_cores_used': cpu_count(),
            'unique_keys_found': len(reduced)
        },
        'metrics': metrics,
        'raw_counts': {k: v for k, v in reduced.items() if not any(x in k for x in ['total_response', 'avg_', 'max_', 'min_'])},
        'insights': insights,
        'performance': {
            'avg_response_time_ms': reduced.get('avg_response_time_ms', 0),
            'max_response_time_ms': reduced.get('max_response_time_ms', 0),
            'total_response_size_bytes': reduced.get('total_response_size', 0)
        }
    }
    
    return result

def run_quick_analysis(lines: List[str]) -> Dict[str, Any]:
    """Quick analysis without full MapReduce (for small files)"""
    if len(lines) < 100:
        # Use single-threaded analysis for small files
        mapped = mapper(lines)
        grouped = defaultdict(list)
        for key, value in mapped:
            grouped[key].append(value)
        reduced = reduce(grouped)
        metrics = analyze_performance_metrics(reduced)
        
        return {
            'summary': {
                'total_lines_processed': len(lines),
                'parallel_chunks': 1,
                'cpu_cores_used': 1,
                'mode': 'single-threaded (small file)'
            },
            'metrics': metrics,
            'raw_counts': reduced,
            'insights': generate_insights(metrics)
        }
    else:
        return run_mapreduce(lines)