#!/usr/bin/env python3
"""
BIKE KEM Computational Cost Evaluation Plotter
Reads evaluation results from CSV and generates visualization
"""

import csv
import sys
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

def print_normalized_chart(results):
    """Print ASCII chart with normalized costs (0-1 scale)"""
    print("\n" + "="*60)
    print("Total Computational Cost (Normalized 0-1 Scale)")
    print("="*60 + "\n")
    
    if not results:
        print("No data to display")
        return
    
    # Create ASCII chart
    chart_height = 30
    num_bars = len(results)
    
    # Print header
    print("  1.0 |", end="")
    for _ in range(num_bars * 8):
        print("-", end="")
    print()
    
    # Print bars
    for level in range(chart_height, 0, -1):
        threshold = level / chart_height
        print(f"  {threshold:.2f} |", end="")
        for result in results:
            normalized = result['normalized']
            bar_height = int((normalized * chart_height))
            if bar_height >= level:
                print("  █████  ", end="")
            else:
                print("        ", end="")
        print()
    
    # Print baseline
    print("  0.00 +", end="")
    for _ in range(num_bars * 8):
        print("-", end="")
    print()
    
    # Print x-axis labels (key sizes)
    print("       ", end="")
    for result in results:
        print(f"{result['key_size']:>7}B", end="")
    print("\n")

def print_table(results):
    """Print results as formatted table"""
    print("="*80)
    print("BIKE KEM Total Computational Cost Analysis")
    print("="*80 + "\n")
    
    print(f"{'Key Size':>10} | {'Total Cost':>15} | {'Normalized':>12}")
    print("-" * 80)
    
    for result in results:
        print(f"{result['key_size']:>10}B | {result['total_cost']:>15} | {result['normalized']:>12.10f}")
    
    print()

def print_statistics(results):
    """Print summary statistics"""
    if not results:
        return
    
    avg_normalized = sum(r['normalized'] for r in results) / len(results)
    max_normalized = max(r['normalized'] for r in results)
    min_normalized = min(r['normalized'] for r in results)
    avg_cost = sum(r['total_cost'] for r in results) / len(results)
    max_cost = max(r['total_cost'] for r in results)
    
    print("="*80)
    print("Summary Statistics")
    print("="*80 + "\n")
    
    print(f"Total key sizes tested:        {len(results)}")
    print(f"Average total cost:            {avg_cost:.2f}")
    print(f"Maximum total cost:            {max_cost:d}")
    print(f"Average normalized cost:       {avg_normalized:.10f}")
    print(f"Minimum normalized cost:       {min_normalized:.10f}")
    print(f"Maximum normalized cost:       {max_normalized:.10f}")
    print()

def main():
    csv_file = "bike_eval_results.csv"
    
    # Read CSV data
    results = read_csv(csv_file)
    
    if not results:
        print("No data found in CSV file")
        return
    
    # Print results
    print_table(results)
    print_statistics(results)
    print_normalized_chart(results)
    
    print("="*80)
    print("Visualization complete!")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
