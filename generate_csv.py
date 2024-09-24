import os
import networkx as nx
import csv
import numpy as np
from multiprocessing import Pool
import logging
import lmoments3 as lmoments


# Set up logging to both console and file
log_filename = 'process_log.txt'
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
                    handlers=[logging.FileHandler(log_filename), logging.StreamHandler()])

# File to store unprocessed files and their error messages
unprocessed_files_log = 'unprocessed_files.csv'
processed_files = set()

# Function to log unprocessed files
def log_unprocessed_file(file_path, error_message):
    with open(unprocessed_files_log, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([file_path, error_message])

# Function to calculate L-moments
def calculate_lmoments(values):
    values = np.array(values)
    values = values[np.isfinite(values)]
    if len(values) < 4:
        return 0, 0, 0, 0
    lmom = lmoments.lmom_ratios(values, nmom=4)

    # Access values by index since lmoments.lmom_ratios returns a tuple
    return lmom[0], lmom[1], lmom[2], lmom[3]

# Function to calculate degree centrality
def calculate_degree_centrality(adj_matrix):
    return np.sum(adj_matrix, axis=1)

# Parse the network data
def parse_network_data(file_path):
    try:
        logging.info(f"Parsing file: {file_path}")
        G = nx.DiGraph(nx.nx_pydot.read_dot(file_path))
        return G
    except Exception as e:
        logging.error(f"Error parsing {file_path}: {e}")
        log_unprocessed_file(file_path, f"Error parsing: {e}")
        return None

# Calculate statistics for the graph
def calculate_statistics(G):
    try:
        num_nodes = G.number_of_nodes()
        num_edges = G.number_of_edges()
        avg_degree = sum(dict(G.degree()).values()) / num_nodes if num_nodes > 0 else 0
        density = nx.density(G)
        diameter = nx.diameter(G) if nx.is_connected(G.to_undirected()) else float('nan')
        avg_clustering_coefficient = nx.average_clustering(G.to_undirected())
        avg_path_length = nx.average_shortest_path_length(G) if nx.is_connected(G.to_undirected()) else float('nan')
        return num_nodes, num_edges, avg_degree, density, diameter, avg_clustering_coefficient, avg_path_length
    except Exception as e:
        logging.error(f"Error calculating statistics: {e}")
        return None

# Calculate centrality measures
def calculate_centrality_measures(G):
    try:
        adj_matrix = nx.to_numpy_array(G).astype(np.float32)
        degree_centrality = calculate_degree_centrality(adj_matrix)

        betweenness_centrality = list(nx.betweenness_centrality(G).values())
        closeness_centrality = list(nx.closeness_centrality(G).values())
        clustering_centrality = list(nx.clustering(G.to_undirected()).values())

        return degree_centrality, betweenness_centrality, closeness_centrality, clustering_centrality
    except Exception as e:
        logging.error(f"Error calculating centrality measures: {e}")
        return None, None, None, None

# Process a single file
def process_file(args):
    file_path, is_malicious = args

    # Skip if the file has already been processed
    if file_path in processed_files:
        logging.info(f"Skipping already processed file: {file_path}")
        return None

    logging.info(f"Processing file: {file_path}")

    G = parse_network_data(file_path)

    if G is None or G.number_of_nodes() == 0 or G.number_of_edges() == 0:
        logging.info(f"Skipping file {file_path} because the graph is empty or couldn't be parsed.")
        log_unprocessed_file(file_path, "Graph is empty or couldn't be parsed.")
        return None

    malware_name = 'Malicious' if is_malicious else 'Nonmalicious'
    logging.info(f"File classified as: {malware_name}")

    stats = calculate_statistics(G)
    if stats is None:
        logging.info(f"Error calculating statistics for {file_path}")
        log_unprocessed_file(file_path, "Error calculating statistics")
        return None
    num_nodes, num_edges, avg_degree, density, diameter, avg_clustering_coefficient, avg_path_length = stats

    if num_nodes == 0:
        logging.info(f"Skipping file {file_path} because the number of nodes is zero.")
        log_unprocessed_file(file_path, "Number of nodes is zero")
        return None

    try:
        logging.info(f"Calculating centrality measures for {file_path}")
        degree_centrality, betweenness_centrality, closeness_centrality, clustering_centrality = calculate_centrality_measures(G)

        if degree_centrality is None:
            logging.info(f"Error calculating centrality measures for {file_path}")
            log_unprocessed_file(file_path, "Error calculating centrality measures")
            return None

        logging.info(f"Calculating L-moments for {file_path}")
        degree_lmoments = calculate_lmoments(degree_centrality)
        betweenness_lmoments = calculate_lmoments(betweenness_centrality)
        closeness_lmoments = calculate_lmoments(closeness_centrality)
        clustering_lmoments = calculate_lmoments(clustering_centrality)

        row = [file_path, malware_name, num_nodes, num_edges, avg_degree, density, diameter,
               avg_clustering_coefficient, avg_path_length] + list(degree_lmoments) + list(betweenness_lmoments) + list(closeness_lmoments) + list(clustering_lmoments)

        logging.info(f"Finished processing {file_path}")
        return row
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        log_unprocessed_file(file_path, f"Error processing: {e}")
        return None

# Write result to CSV
def write_result_to_csv(row, writer, csvfile):
    if row:
        writer.writerow(row)
        csvfile.flush()  # Flush the file to make sure data is saved immediately

# Read existing processed files from the CSV
def get_processed_files(csvfile_path):
    processed_files = set()
    if os.path.exists(csvfile_path):
        with open(csvfile_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip header
            for row in reader:
                if row:
                    processed_files.add(row[0].strip())  # Strip any whitespace or newline characters
    return processed_files

# Main function
def main():
    global processed_files  # Mark processed_files as global so it's accessible in the multiprocessing workers

    malicious_directory = 'Malicious'
    nonmalicious_directory = 'Nonmalicious'
    output_csv = 'lmoments.csv'

    # Initialize CSV file for unprocessed files
    if not os.path.exists(unprocessed_files_log):
        with open(unprocessed_files_log, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Filename', 'Error Message'])

    # Get already processed files
    processed_files = get_processed_files(output_csv)

    file_paths = []
    for root, _, files in os.walk(malicious_directory):
        for filename in files:
            if filename.endswith('.dot'):
                file_path = os.path.join(root, filename)
                if file_path not in processed_files:  # Skip if already processed
                    logging.info(f"Found file in Malicious: {filename}")
                    file_paths.append((file_path, True))

    for root, _, files in os.walk(nonmalicious_directory):
        for filename in files:
            if filename.endswith('.dot'):
                file_path = os.path.join(root, filename)
                if file_path not in processed_files:  # Skip if already processed
                    logging.info(f"Found file in Nonmalicious: {filename}")
                    file_paths.append((file_path, False))

    if not file_paths:
        logging.info("No .dot files found in the specified directories!")
        return

    total_files = len(file_paths)
    processed_files_count = 0

    with open(output_csv, mode='a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        if os.stat(output_csv).st_size == 0:
            columns = ['Filename', 'Malicious/Nonmalicious', 'Number of Nodes', 'Number of Edges', 'Average Degree',
                       'Density', 'Diameter', 'Average Clustering', 'Average Path Length',
                       'Degree L1', 'Degree L2', 'Degree T3', 'Degree T4',
                       'Betweenness L1', 'Betweenness L2', 'Betweenness T3', 'Betweenness T4',
                       'Closeness L1', 'Closeness L2', 'Closeness T3', 'Closeness T4',
                       'Clustering L1', 'Clustering L2', 'Clustering T3', 'Clustering T4']
            writer.writerow(columns)
            csvfile.flush()

        # Define the number of CPU cores to use
        num_cores = 25  # You can adjust this value

        with Pool(num_cores) as pool:
            for result in pool.imap_unordered(process_file, file_paths):
                processed_files_count += 1
                if result:
                    write_result_to_csv(result, writer, csvfile)
                    processed_files.add(result[0])  # Add the processed file to the set
                logging.info(f"Progress: {processed_files_count}/{total_files} files processed.")

    logging.info('L-moments and statistics CSV file has been created successfully.')

if __name__ == '__main__':
    main()
