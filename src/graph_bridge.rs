#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("graph_generator.h");
    }
}
