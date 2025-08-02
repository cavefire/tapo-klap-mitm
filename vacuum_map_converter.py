#!/usr/bin/env python3
"""
Map to PNG Converter
"""

import json
import base64
import lz4.block
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import sys
import os

def load_map_data(json_file_path):
    """Load and parse the map response JSON file."""
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Error: File '{json_file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file '{json_file_path}'.")
        sys.exit(1)

def decode_room_name(encoded_name):
    """Decode base64 encoded room name."""
    try:
        decoded_bytes = base64.b64decode(encoded_name)
        return decoded_bytes.decode('utf-8')
    except:
        return encoded_name

def decompress_map_data(map_response):
    """Extract and decompress the map data from the response."""
    map_data = map_response['result']['responses'][0]['result']
    width = map_data['width']
    height = map_data['height']
    compressed_data = map_data['map_data']
    bit_list = map_data['bit_list']
    pix_len = map_data['pix_len']
    area_list = map_data.get('area_list', [])
    print(f"Map dimensions: {width} x {height}")
    print(f"Expected uncompressed size: {pix_len} bytes")
    print(f"Bit mapping: {bit_list}")
    if area_list:
        print("Room areas found:")
        for area in area_list:
            room_name = decode_room_name(area.get('name', 'Unknown'))
            print(f"  Room {area['id']}: {room_name} (color {area['color']})")
    try:
        compressed_bytes = base64.b64decode(compressed_data)
        print(f"Compressed data size: {len(compressed_bytes)} bytes")
        decompressed_data = lz4.block.decompress(compressed_bytes, uncompressed_size=pix_len)
        print(f"Successfully decompressed data size: {len(decompressed_data)} bytes")
        return decompressed_data, width, height, bit_list, area_list
    except Exception as e:
        print(f"Error processing data: {e}")
        sys.exit(1)

def create_enhanced_image(decompressed_data, width, height, bit_list, area_list):
    """Convert the decompressed map data to a PIL Image with enhanced room visualization."""
    map_array = np.frombuffer(decompressed_data, dtype=np.uint8)
    map_2d = map_array.reshape((height, width))
    rgb_image = np.zeros((height, width, 3), dtype=np.uint8)
    base_colors = {
        bit_list['barrier']: [0, 0, 0],
        bit_list['none']: [200, 200, 200],
        bit_list['clean']: [255, 255, 255],
    }
    if 'auto_area' in bit_list and isinstance(bit_list['auto_area'], list):
        for i, area_value in enumerate(bit_list['auto_area']):
            if area_value != bit_list['barrier']:
                base_colors[area_value] = [150, 200, 150]
    room_colors = {}
    if area_list:
        room_color_palette = [
            [255, 230, 230],
            [230, 255, 230],
            [230, 230, 255],
            [255, 255, 230],
            [255, 230, 255],
            [230, 255, 255],
            [255, 200, 150],
            [200, 255, 150],
        ]
        for i, area in enumerate(area_list):
            room_id = area['id']
            color_idx = (i) % len(room_color_palette)
            room_colors[room_id] = room_color_palette[color_idx]
    for value, color in base_colors.items():
        mask = map_2d == value
        rgb_image[mask] = color
    unique_values = set(np.unique(map_2d))
    for value in unique_values:
        if value in room_colors:
            mask = map_2d == value
            rgb_image[mask] = room_colors[value]
        elif value not in base_colors:
            mask = map_2d == value
            intensity = min(255, 100 + (int(value) * 30) % 155)
            rgb_image[mask] = [intensity, max(0, intensity - 50), max(0, intensity - 100)]
    print(f"Unique pixel values in map: {sorted(unique_values)}")
    image = Image.fromarray(rgb_image, 'RGB')
    scale_factor = 4
    scaled_width = width * scale_factor
    scaled_height = height * scale_factor
    image = image.resize((scaled_width, scaled_height), Image.Resampling.NEAREST)
    if area_list:
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 20)
        except:
            try:
                font = ImageFont.load_default()
            except:
                font = None
        for area in area_list:
            room_id = area['id']
            room_name = decode_room_name(area.get('name', f'Room {room_id}'))
            room_mask = map_2d == room_id
            if np.any(room_mask):
                y_coords, x_coords = np.where(room_mask)
                center_x = int(np.mean(x_coords) * scale_factor)
                center_y = int(np.mean(y_coords) * scale_factor)
                if font:
                    bbox = draw.textbbox((0, 0), room_name, font=font)
                    text_width = bbox[2] - bbox[0]
                    text_height = bbox[3] - bbox[1]
                    text_x = center_x - text_width // 2
                    text_y = center_y - text_height // 2
                    draw.rectangle([text_x - 2, text_y - 2, text_x + text_width + 2, text_y + text_height + 2], 
                                 fill=(255, 255, 255, 180))
                    draw.text((text_x, text_y), room_name, fill=(0, 0, 0), font=font)
                else:
                    draw.text((center_x, center_y), room_name, fill=(0, 0, 0))
    return image

def main():
    """Main function to convert map data to PNG."""
    input_file = "map_response.json"
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        print("Usage: python vacuum_map_converter.py [input_file.json]")
        sys.exit(1)
    print(f"Loading map data from: {input_file}")
    map_response = load_map_data(input_file)
    decompressed_data, width, height, bit_list, area_list = decompress_map_data(map_response)
    image = create_enhanced_image(decompressed_data, width, height, bit_list, area_list)
    base_name = os.path.splitext(input_file)[0]
    output_file = f"{base_name}_floor_plan.png"
    image.save(output_file)
    print(f"\nFloor plan image saved as: {output_file}")
    print(f"Original map size: {width} x {height} pixels")
    print(f"Output image size: {image.size}")
    print(f"Resolution: 50mm per pixel")
    real_width_mm = width * 50
    real_height_mm = height * 50
    print(f"Real-world dimensions: {real_width_mm/1000:.1f}m x {real_height_mm/1000:.1f}m")
    if area_list:
        print(f"Room areas: {len(area_list)} rooms detected and labeled")

if __name__ == "__main__":
    main()
