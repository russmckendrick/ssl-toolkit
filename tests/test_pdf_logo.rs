#[test]
fn test_logo_render() {
    use std::io::Cursor;

    // Just test the SVG parsing and rendering
    let svg_data = include_bytes!("../assets/logo.svg");
    println!("SVG data size: {} bytes", svg_data.len());

    let opt = usvg::Options::default();
    let tree = usvg::Tree::from_data(svg_data, &opt).expect("Failed to parse SVG");
    println!("SVG parsed! Size: {}x{}", tree.size().width(), tree.size().height());

    let target_height = 80.0;
    let scale = target_height / tree.size().height();
    let width = (tree.size().width() * scale) as u32;
    let height = target_height as u32;
    println!("Target size: {}x{}, scale: {}", width, height, scale);

    let mut pixmap = tiny_skia::Pixmap::new(width, height).expect("Failed to create pixmap");

    // Fill with white background first
    pixmap.fill(tiny_skia::Color::WHITE);

    let transform = tiny_skia::Transform::from_scale(scale, scale);
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    // Convert RGBA to RGB (remove alpha channel)
    let rgba_data = pixmap.data();
    let mut rgb_data = Vec::with_capacity((width * height * 3) as usize);
    for pixel in rgba_data.chunks(4) {
        rgb_data.push(pixel[0]); // R
        rgb_data.push(pixel[1]); // G
        rgb_data.push(pixel[2]); // B
    }

    // Encode as RGB PNG (no alpha)
    let mut png_data = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut png_data), width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("PNG header failed");
        writer.write_image_data(&rgb_data).expect("PNG data failed");
    }

    println!("PNG encoded (RGB)! Size: {} bytes", png_data.len());

    // Save for inspection
    std::fs::write("/tmp/ssl_toolkit_logo_test_rgb.png", &png_data).unwrap();
    println!("Saved to /tmp/ssl_toolkit_logo_test_rgb.png");

    // Test loading with genpdf
    use genpdf::elements::Image;
    match Image::from_reader(Cursor::new(&png_data)) {
        Ok(_) => println!("genpdf Image loaded successfully!"),
        Err(e) => panic!("genpdf Image load failed: {:?}", e),
    }
}
