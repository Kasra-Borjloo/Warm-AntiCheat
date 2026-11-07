#[cfg(target_os = "windows")]
pub fn capture_screenshot() -> Option<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    unsafe {
        let hdc_screen = GetDC(ptr::null_mut());
        if hdc_screen.is_null() {
            return None;
        }

        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        if width <= 0 || height <= 0 || width > 16384 || height > 16384 {
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return None;
        }

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_null() {
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return None;
        }

        let hbitmap = CreateCompatibleBitmap(hdc_screen, width, height);
        if hbitmap.is_null() {
            DeleteDC(hdc_mem);
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return None;
        }

        let old_obj = SelectObject(hdc_mem, hbitmap);
        let blt_res = BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);
        if blt_res == 0 {
            SelectObject(hdc_mem, old_obj);
            DeleteObject(hbitmap);
            DeleteDC(hdc_mem);
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return None;
        }

        let mut bi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height,
                biPlanes: 1,
                biBitCount: 24,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD {
                rgbBlue: 0,
                rgbGreen: 0,
                rgbRed: 0,
                rgbReserved: 0,
            }],
        };

        let row_stride = ((width * 3 + 3) / 4) * 4;
        let img_bytes_len = (row_stride * height) as usize;
        let mut pixels = vec![0u8; img_bytes_len];

        let dib_res = GetDIBits(
            hdc_mem,
            hbitmap,
            0,
            height as u32,
            pixels.as_mut_ptr() as _,
            &mut bi,
            DIB_RGB_COLORS,
        );

        SelectObject(hdc_mem, old_obj);
        DeleteObject(hbitmap);
        DeleteDC(hdc_mem);
        ReleaseDC(ptr::null_mut(), hdc_screen);

        if dib_res == 0 {
            return None;
        }

        let mut rgb = Vec::with_capacity((width * height * 3) as usize);
        for y in 0..height {
            let row_start = (y as usize) * (row_stride as usize);
            for x in 0..width {
                let src = row_start + (x as usize) * 3;
                let b = pixels[src];
                let g = pixels[src + 1];
                let r = pixels[src + 2];
                rgb.push(r);
                rgb.push(g);
                rgb.push(b);
            }
        }

        let mut jpeg_bytes = Vec::new();
        let encoder = jpeg_encoder::Encoder::new(&mut jpeg_bytes, 75);
        if encoder
            .encode(
                &rgb,
                width as u16,
                height as u16,
                jpeg_encoder::ColorType::Rgb,
            )
            .is_ok()
        {
            Some(jpeg_bytes)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn capture_screenshot() -> Option<Vec<u8>> {
    None
}
