-- Add multiple image columns to the books table
ALTER TABLE books 
ADD COLUMN front_image VARCHAR(255) AFTER image_url,
ADD COLUMN back_image VARCHAR(255) AFTER front_image,
ADD COLUMN inside_image VARCHAR(255) AFTER back_image;

-- Update existing records to use image_url as front_image
UPDATE books SET front_image = image_url WHERE image_url IS NOT NULL;

-- Add indexes for performance
ALTER TABLE books ADD INDEX idx_category (category);
ALTER TABLE books ADD INDEX idx_status (status); 