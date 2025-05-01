from PIL import Image
import random
import os, shutil
import re
import multiprocessing
from tqdm import tqdm
import time
import argparse



def Image_Shuffler(image_path:str, num_parts:int, output_path:str) -> None:

    # Load the image
    image = Image.open(image_path)
    width, height = image.size


    rows = cols = int(num_parts ** 0.5)

    if rows * cols != num_parts:
        raise ValueError("The number of parts must be a perfect square.")

    # Calculate the size of each part
    part_width = width // cols
    part_height = height // rows

    # Split the image into parts
    parts = []
    for row in range(rows):
        for col in range(cols):
            left = col * part_width
            upper = row * part_height
            right = left + part_width
            lower = upper + part_height
            part = image.crop((left, upper, right, lower))
            parts.append(part)

    # Shuffle the parts
    random.shuffle(parts)

    # Create a new blank image to hold the shuffled parts
    shuffled_image = Image.new("RGB", (width, height))

    # Paste the shuffled parts back into the new image
    index = 0
    for row in range(rows):
        for col in range(cols):
            left = col * part_width
            upper = row * part_height
            shuffled_image.paste(parts[index], (left, upper))
            index += 1

    # Save the shuffled image
    shuffled_image.save(output_path)
    print(f"Shuffled image saved as '{os.path.basename(output_path)}'")
    


def text_shuffler(src_path:str, dst_path:str)->None:
    with open(src_path, 'r') as f:
        text_contents = f.read()
    
    tokens = re.split( r"[\s\.\n]", text_contents)
    random.shuffle(tokens)
    
    with open(dst_path, 'w') as f:
        f.write(' '.join(tokens))
        
    print(f"Shuffled text saved as '{os.path.basename(dst_path)}'")
    


def get_folder_size_of_files(folder_path:str)->int:
    
    return sum(os.path.getsize(os.path.join(folder_path, f)) for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f)))


def populate_folder_with_files(target_folder:str, sample_img:str, sample_txt:str, sample_folder:str, target_size:int=5000)->None:
    counter = 0
    while (get_folder_size_of_files(target_folder) < target_size):
        
            # if (random.choice([0,1]) == 1):
            #     Image_Shuffler(image_path=sample_img, num_parts=81, output_path=os.path.join(target_folder, f"image_{counter}.png"))
            #     counter += 1
            
            # if (random.choice([0,1]) == 1):
            #     text_shuffler(src_path=sample_txt, dst_path=os.path.join(target_folder, f"text_{counter}.txt"))
            #     counter += 1
            
            
            files = [i for i in os.listdir(sample_folder) if os.path.isfile(os.path.join(sample_folder, i)) ]
            for file in files:
                shutil.copy(src=os.path.join(sample_folder, file),  dst=os.path.join(target_folder, f"file_{counter}{os.path.splitext(file)[1]}"))
                counter += 1


def populate_folder_with_folders(target_folder:str, target_count=10)->None:
    folder_count = 0
    while folder_count < target_count:
        folder_count += 1
        os.mkdir(os.path.join(target_folder, f"Folder_{folder_count}"))


def recursive_folder_population(start_folder:str, curr_depth:int=1, max_depth:int=4, folder_count_per_step:int=10)->None:
    # print(f"Populating {start_folder} with empty folders...")
    if(curr_depth > max_depth):
        return
    populate_folder_with_folders(target_folder=start_folder, target_count=folder_count_per_step)
    
    folders = [i for i in os.listdir(start_folder) if os.path.isdir(os.path.join(start_folder, i))]
    curr_depth += 1
    for fold in folders:
        recursive_folder_population(start_folder=os.path.join(start_folder, fold), curr_depth=curr_depth, max_depth=max_depth)
        

def recursive_file_population(start_folder:str, samples_folder:str, one_folder_size:int=5000)->None:
    # print(f"Populating {start_folder} with Files...")
    populate_folder_with_files(target_folder=start_folder, sample_img=os.path.join(samples_folder, "image.png"),
                               sample_txt=os.path.join(samples_folder, "text.txt"),
                               sample_folder=samples_folder,
                               target_size=one_folder_size)

    
    folders = [i for i in os.listdir(start_folder) if os.path.isdir(os.path.join(start_folder, i))]
    for fold in folders:
        recursive_file_population(start_folder=os.path.join(start_folder, fold), samples_folder=samples_folder, one_folder_size=one_folder_size)
    
    

def get_recursive_folder_size(start_path = '.'):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)

    return total_size






def start_progress_bar_process(target_folder: str, target_size: int):
    progress_process = multiprocessing.Process(target=progress_bar, args=(target_folder, target_size), daemon=True)
    progress_process.start()
    
    
def progress_bar(target_folder: str, target_size: int):
    with tqdm(total=target_size, desc="Folder Size Progress", unit="B", unit_scale=True) as pbar:
        while True:
            current_size = get_recursive_folder_size(target_folder)
            # print(current_size)
            pbar.n = current_size
            pbar.refresh()
            if current_size >= target_size:
                break
            time.sleep(0.3)  # Adjust the sleep time as needed




if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Populator',
                    description='This script simple populates a target folder with fuzzy files taken from a sample folder',
                    epilog='For more info, please contact Ayman Mohamed Reda via https://www.linkedin.com/in/ayman-reda-b845b0203/')
    parser.add_argument('folderpath', type=str, default="./populated", help="Path to the target folder, it must be empty or non-existent")
    parser.add_argument('-d', '--maxdepth', type=int, default=2, help="Max Depth of nested folders")
    parser.add_argument('-s', '--foldersize', type=int, default=5000 , help="Intended size of 1 folder in Bytes, not the overall size after finishing")
    parser.add_argument('-c', '--foldercount', type=int, default=10 , help="Folders count per each nested folder")
    parser.add_argument('-i', '--samples', type=str, default="./samples" , help="Path to a folder containing some sample files to copy from")
    
    args = parser.parse_args()
    
    
    samples_folder = args.samples
    populated_folder = args.folderpath
    max_depth = args.maxdepth
    folder_count = args.foldercount
    foldersize = args.foldersize
    if not os.path.exists(populated_folder): os.mkdir(populated_folder)
    populated_folder = os.path.abspath(populated_folder)
    
    
    start_progress_bar_process(target_folder=populated_folder, target_size=2000000000)
    recursive_folder_population(start_folder=populated_folder, curr_depth=1, max_depth=max_depth, folder_count_per_step=folder_count)
    recursive_file_population(start_folder=populated_folder, samples_folder=samples_folder, one_folder_size=foldersize)
    
    
    
    
        
        