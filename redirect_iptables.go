//go:build linux

package tun

import (
	"os/exec"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

func (r *autoRedirect) setupIPTables() error {
	if r.enableIPv4 {
		err := r.setupIPTablesForFamily(r.iptablesPath, r.enablePreRouting4)
		if err != nil {
			return E.Cause(err, "setup iptables")
		}
	}
	if r.enableIPv6 {
		err := r.setupIPTablesForFamily(r.ip6tablesPath, r.enablePreRouting6)
		if err != nil {
			return E.Cause(err, "setup ip6tables")
		}
	}
	return nil
}

func (r *autoRedirect) setupIPTablesForFamily(iptablesPath string, enablePreRouting bool) error {
	tableNameOutput := r.tableName + "-output"
	redirectPort := r.redirectPort()
	// OUTPUT
	err := r.runShell(iptablesPath, "-t nat -N", tableNameOutput)
	if err != nil {
		return err
	}
	err = r.runShell(iptablesPath, "-t nat -A", tableNameOutput,
		"-p tcp -o", r.tunOptions.Name,
		"-j REDIRECT --to-ports", redirectPort)
	if err != nil {
		return err
	}
	err = r.runShell(iptablesPath, "-t nat -I OUTPUT -j", tableNameOutput)
	if err != nil {
		return err
	}
	if enablePreRouting {
		err = r.setupIPTablesPreRouting(iptablesPath)
		if err != nil {
			r.cleanupIPTablesPreRouting(iptablesPath)
			r.logger.Warn("setup nat PREROUTING rules: ", err)
		}
	}
	return nil
}

func (r *autoRedirect) setupIPTablesPreRouting(iptablesPath string) error {
	tableNamePreRouting := r.tableName + "-prerouting"
	redirectPort := r.redirectPort()
	err := r.runShell(iptablesPath, "-t nat -N", tableNamePreRouting)
	if err != nil {
		return err
	}
	err = r.runShell(iptablesPath, "-t nat -A", tableNamePreRouting,
		"-i", r.tunOptions.Name, "-j RETURN")
	if err != nil {
		return err
	}
	for _, name := range r.tunOptions.ExcludeInterface {
		err = r.runShell(iptablesPath, "-t nat -A", tableNamePreRouting,
			"-i", name, "-j RETURN")
		if err != nil {
			return err
		}
	}
	err = r.runShell(iptablesPath, "-t nat -A", tableNamePreRouting,
		"-m addrtype --dst-type LOCAL -j RETURN")
	if err != nil {
		return err
	}
	err = r.runShell(iptablesPath, "-t nat -A", tableNamePreRouting,
		"-p tcp -j REDIRECT --to-ports", redirectPort)
	if err != nil {
		return err
	}
	if len(r.tunOptions.IncludeInterface) > 0 {
		for _, name := range r.tunOptions.IncludeInterface {
			err = r.runShell(iptablesPath, "-t nat -I PREROUTING -i", name, "-j", tableNamePreRouting)
			if err != nil {
				return err
			}
		}
	} else {
		err = r.runShell(iptablesPath, "-t nat -I PREROUTING -j", tableNamePreRouting)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *autoRedirect) cleanupIPTables() {
	if r.enableIPv4 {
		r.cleanupIPTablesForFamily(r.iptablesPath, r.enablePreRouting4)
	}
	if r.enableIPv6 {
		r.cleanupIPTablesForFamily(r.ip6tablesPath, r.enablePreRouting6)
	}
}

func (r *autoRedirect) cleanupIPTablesForFamily(iptablesPath string, enablePreRouting bool) {
	tableNameOutput := r.tableName + "-output"

	_ = r.runShell(iptablesPath, "-t nat -D OUTPUT -j", tableNameOutput)
	_ = r.runShell(iptablesPath, "-t nat -F", tableNameOutput)
	_ = r.runShell(iptablesPath, "-t nat -X", tableNameOutput)
	if enablePreRouting {
		r.cleanupIPTablesPreRouting(iptablesPath)
	}
}

func (r *autoRedirect) cleanupIPTablesPreRouting(iptablesPath string) {
	tableNamePreRouting := r.tableName + "-prerouting"
	if len(r.tunOptions.IncludeInterface) > 0 {
		for _, name := range r.tunOptions.IncludeInterface {
			_ = r.runShell(iptablesPath, "-t nat -D PREROUTING -i", name, "-j", tableNamePreRouting)
		}
	} else {
		_ = r.runShell(iptablesPath, "-t nat -D PREROUTING -j", tableNamePreRouting)
	}
	_ = r.runShell(iptablesPath, "-t nat -F", tableNamePreRouting)
	_ = r.runShell(iptablesPath, "-t nat -X", tableNamePreRouting)
}

func (r *autoRedirect) runShell(commands ...any) error {
	commandStr := strings.Join(F.MapToString(commands), " ")
	var command *exec.Cmd
	if r.androidSu {
		command = exec.Command(r.suPath, "-c", commandStr)
	} else {
		commandArray := strings.Split(commandStr, " ")
		command = exec.Command(commandArray[0], commandArray[1:]...)
	}
	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		return E.Extend(err, F.ToString(commandStr, ": ", string(combinedOutput)))
	}
	return nil
}
