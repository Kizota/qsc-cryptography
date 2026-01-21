#!/usr/bin/env python3
"""
BIKE KEM Computational Cost Evaluation - Visual Plotter with Matplotlib
Reads evaluation results from CSV and generates colorful visualizations
"""

import csv
import sys
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

def read_csv(filename):
    """Read evaluation results from CSV file"""
    results = []
    try:
        with open(filename, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append({
                    'key_size': int(row['KeySize']),
                    'total_cost': int(row['TotalComputationalCost']),
                })
        # Add normalization for plotting (computed from total cost)
        if results:
            max_cost = max(r['total_cost'] for r in results) or 1
            for r in results:
                r['normalized'] = r['total_cost'] / max_cost
        return results
    except FileNotFoundError:
        print(f"Error: {filename} not found. Run 'bike_eval.exe' first.")
        sys.exit(1)

def create_visualizations(results):
    """Create cost trend line chart visualization"""
    
    if not results:
        print("No data to visualize")
        return
    
    # Extract data
    key_sizes = [r['key_size'] for r in results]
    normalized = [r['normalized'] for r in results]
    total_cost = [r['total_cost'] for r in results]
    
    # Create figure with single plot
    fig = plt.figure(figsize=(14, 8))
    fig.suptitle('BIKE KEM Computational Cost Analysis', fontsize=18, fontweight='bold')
    
    # ===== Cost Trend Line Chart =====
    ax = plt.subplot(1, 1, 1)
    line = ax.plot(key_sizes, normalized, linewidth=3, color='#2E86AB', marker='o', markersize=8, label='Total Cost')
    ax.fill_between(key_sizes, normalized, alpha=0.25, color='#2E86AB')
    
    ax.set_xlabel('Key Size (Bytes)', fontweight='bold', fontsize=13)
    ax.set_ylabel('Normalized Total Computational Cost (0-1)', fontweight='bold', fontsize=13)
    ax.set_title('Total Computational Cost Trend', fontweight='bold', fontsize=14, pad=20)
    ax.set_ylim([0, 1.05])
    ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8)
    ax.legend(fontsize=12, loc='best')
    
    # Add value annotations for key points
    min_idx = normalized.index(min(normalized))
    max_idx = normalized.index(max(normalized))
    
    ax.annotate(f"Min: {normalized[min_idx]:.4f} ({total_cost[min_idx]})", 
                xy=(key_sizes[min_idx], normalized[min_idx]),
                xytext=(10, -15), textcoords='offset points',
                bbox=dict(boxstyle='round,pad=0.5', fc='yellow', alpha=0.7),
                arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0', color='black', lw=1.5),
                fontsize=11, fontweight='bold')
    
    ax.annotate(f"Max: {normalized[max_idx]:.4f} ({total_cost[max_idx]})", 
                xy=(key_sizes[max_idx], normalized[max_idx]),
                xytext=(10, 15), textcoords='offset points',
                bbox=dict(boxstyle='round,pad=0.5', fc='lightgreen', alpha=0.7),
                arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0', color='black', lw=1.5),
                fontsize=11, fontweight='bold')
    
    # Adjust layout
    plt.tight_layout()
    
    # Save to file
    import os
    cwd = os.getcwd()
    output_file = os.path.join(cwd, "bike_eval_results.png")
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"\n✓ Visualization saved to: {output_file}")
    
    # Show the figure
    print("Opening visualization window...")
    plt.show()

def main():
    csv_file = "bike_eval_results.csv"
    
    # Read CSV data
    results = read_csv(csv_file)
    
    if not results:
        print("No data found in CSV file")
        return
    
    # Get current working directory
    import os
    cwd = os.getcwd()
    output_png = os.path.join(cwd, "bike_eval_results.png")
    
    # Create and display visualizations
    print(f"Loading {len(results)} data points from {csv_file}...")
    print(f"Working directory: {cwd}")
    print("Generating colorful visualizations...")
    create_visualizations(results)

if __name__ == "__main__":
    main()
