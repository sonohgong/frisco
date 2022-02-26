/// Interfaces
///
/// Alternative to using pnet just to get the interface addresses + scope_id.
/// This makes it less portable though, as we're now stuck with only linux.
///
extern crate libc;

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type InetAddr = (IpAddr, Option<u32>);

#[derive(Debug)]
pub struct Interfaces {
    ptr_ifa_head: *mut libc::ifaddrs,
    ptr_ifa: *mut libc::ifaddrs,
}

impl Interfaces {
    fn new() -> Interfaces {
        unsafe {
            let mut ptr_ifa_head: *mut libc::ifaddrs = mem::MaybeUninit::uninit().assume_init();
            if libc::getifaddrs(&mut ptr_ifa_head) != 0 {
                panic!("failed to get interface addresses");
            }
            Interfaces {
                ptr_ifa_head,
                ptr_ifa: ptr_ifa_head,
            }
        }
    }
}

impl Drop for Interfaces {
    fn drop(&mut self) -> () {
        unsafe {
            libc::freeifaddrs(self.ptr_ifa_head);
        }
    }
}

impl Iterator for Interfaces {
    type Item = InetAddr;
    fn next(&mut self) -> Option<InetAddr> {
        while !self.ptr_ifa.is_null() {
            unsafe {
                let ifa = *self.ptr_ifa;
                self.ptr_ifa = ifa.ifa_next;

                let ptr_sa = ifa.ifa_addr;

                if !ptr_sa.is_null() {
                    let sa_family = (*ptr_sa).sa_family;
                    match sa_family as i32 {
                        libc::AF_INET => {
                            let sockaddr = ptr_sa as *const libc::sockaddr_in;
                            let s_addr = (*sockaddr).sin_addr.s_addr;
                            // Note that s_addr shouldn't be used as if it was "u32"
                            // because the representation in memory is already network
                            // byte order.
                            let bytes: [u8; 4] = mem::transmute(s_addr);
                            return Some((IpAddr::V4(Ipv4Addr::from(bytes)), None));
                        }
                        libc::AF_INET6 => {
                            let sockaddr = ptr_sa as *const libc::sockaddr_in6;
                            let scope_id = (*sockaddr).sin6_scope_id;
                            let s_addr = (*sockaddr).sin6_addr.s6_addr;
                            return Some((IpAddr::V6(Ipv6Addr::from(s_addr)), Some(scope_id)));
                        }
                        _ => (),
                    };
                }
            }
        }
        return None;
    }
}

pub fn ifaddrs() -> Interfaces {
    return Interfaces::new();
}
