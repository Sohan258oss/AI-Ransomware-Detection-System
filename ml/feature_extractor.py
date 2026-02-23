import pandas as pd

def extract_features(event_log: list) -> dict:
    """
    Convert a time-window of events into ML features.
    event_log: list of dicts with keys: type, entropy, extension, process_cpu, open_files
    """
    if not event_log:
        return {}
    
    df = pd.DataFrame(event_log)
    
    return {
        'file_events_per_sec': len(df),
        'rename_count': len(df[df['type'] == 'renamed']) if 'type' in df.columns else 0,
        'delete_count': len(df[df['type'] == 'deleted']) if 'type' in df.columns else 0,
        'avg_entropy': df['entropy'].mean() if 'entropy' in df.columns else 0,
        'max_entropy': df['entropy'].max() if 'entropy' in df.columns else 0,
        'high_entropy_ratio': (df['entropy'] > 7.0).mean() if 'entropy' in df.columns else 0,
        'avg_cpu': df['process_cpu'].mean() if 'process_cpu' in df.columns else 0,
        'avg_open_files': df['open_files'].mean() if 'open_files' in df.columns else 0,
    }