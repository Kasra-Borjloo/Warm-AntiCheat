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
        if width <= 0 || height <= 0 {
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

        let file_header_len = 14;
        let info_header_len = 40;
        let file_size = (file_header_len + info_header_len + img_bytes_len) as u32;

        let mut bmp = Vec::with_capacity(file_size as usize);
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&file_size.to_le_bytes());
        bmp.extend_from_slice(&[0u8; 4]);
        let offset = (file_header_len + info_header_len) as u32;
        bmp.extend_from_slice(&offset.to_le_bytes());

        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&width.to_le_bytes());
        bmp.extend_from_slice(&(-height).to_le_bytes());
        bmp.extend_from_slice(&1u16.to_le_bytes());
        bmp.extend_from_slice(&24u16.to_le_bytes());
        bmp.extend_from_slice(&BI_RGB.to_le_bytes());
        bmp.extend_from_slice(&(img_bytes_len as u32).to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());

        bmp.extend_from_slice(&pixels);
        Some(bmp)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn capture_screenshot() -> Option<Vec<u8>> {
    None
}
