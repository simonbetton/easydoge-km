Pod::Spec.new do |s|
  s.name = "EasyDogeKMExpo"
  s.version = "0.1.0"
  s.summary = "Expo native module bridge for EasyDoge Dogecoin key management"
  s.description = "Rust-backed Dogecoin key-management SDK for Expo custom dev-client and EAS builds."
  s.license = { :type => "MIT" }
  s.homepage = "https://github.com/simonbetton/easydoge-km"
  s.author = "EasyDoge"
  s.platforms = { :ios => "16.4" }
  s.source = { :git => "https://github.com/simonbetton/easydoge-km.git", :tag => s.version.to_s }
  s.source_files = "ios/**/*.{h,m,mm,swift}"
  s.dependency "ExpoModulesCore"
  s.pod_target_xcconfig = {
    "OTHER_LDFLAGS" => "-L${PODS_TARGET_SRCROOT}/../../../target/release -leasydoge_km_ffi"
  }
end
