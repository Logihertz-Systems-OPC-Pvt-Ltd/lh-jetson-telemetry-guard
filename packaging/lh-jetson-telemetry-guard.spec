Name:           lh-jetson-telemetry-guard
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-telemetry-guard - Shannon Entropy of Outbound DNS & Default-Drop Filter
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jetson-telemetry-guard
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
NVIDIA Jetson L4T & embedded BSP outbound telemetry blocker generating cgroup/connect4 eBPF socket filters, default-drop nftables air-gap rulesets, /etc/hosts sinkholes, and DNS entropy exfiltration alerts.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-telemetry-guard ]; then
    install -m 0755 bin/lh-telemetry-guard %{buildroot}%{_bindir}/lh-telemetry-guard
elif [ -f lh-telemetry-guard ]; then
    install -m 0755 lh-telemetry-guard %{buildroot}%{_bindir}/lh-telemetry-guard
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
