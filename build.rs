fn main() {
    cxx_build::bridge("src/graph_bridge.rs")
        .file("src/cpp/graph_generator.cpp")
        .file("src/cpp/hamiltonian_cpu.cpp")
        .file("src/cpp/hugepage_alloc.cpp")
        .include("src/cpp")
        .flag_if_supported("-UOPENSSL_API_COMPAT")
        .flag_if_supported("-DOPENSSL_API_COMPAT=0x10100000L")
        .std("c++17")
        .compile("shaipot_cpp");

    // Link OpenSSL
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    println!("cargo:rerun-if-changed=src/graph_bridge.rs");
    println!("cargo:rerun-if-changed=src/cpp_bridge.rs");
    println!("cargo:rerun-if-changed=src/cpp/graph_generator.cpp");
    println!("cargo:rerun-if-changed=src/cpp/graph_generator.h");
    println!("cargo:rerun-if-changed=src/cpp/hamiltonian_cpu.cpp");
    println!("cargo:rerun-if-changed=src/cpp/hamiltonian_cpu.h");
    println!("cargo:rerun-if-changed=src/cpp/hugepage_alloc.cpp");
    println!("cargo:rerun-if-changed=src/cpp/hugepage_alloc.h");
}
