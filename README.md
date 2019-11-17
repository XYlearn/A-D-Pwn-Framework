# AWD PWN Framework

This is a pwn framework to do some automation work during AWD competition

## Features

- Easy to deploy and run: oneline to create exp script and oneline to use all of them
- Auto reloading: don't need to restart framework every time you modify `exps` `config.ini` and `targets.json`
- Manage exploits with namespace: you can create a namespace like AAA.BBB.CCC
- Logging: all logs are saved to awd.log.
- Shell maintainance: the framework will bind CLI to specific port. use `python manage.py sm` to start a shell manager client to connect to the cli service and manage shells


## Start it

```shell
# see help
python manage.py --help
# run framework
python manage.py run
```



## Tree View

```shell
.
├── README.md
├── awd.log
├── prelude
│   ├── exp_template.py # exploit template, can be modified
│   ├── targets.json # default json config
├── awdpwn # code of framework
│   ├── __init__.py
│   ├── attack.py # about attack automation
│   ├── config.py	# load target/gamebox non-specific configuration            
│   ├── log.py # get logger
│   ├── shell.py # maintain shells
│   ├── submit.py # default flag submitter
│   ├── utils.py
│   └── watch.py # reload things when exps, targets.json or config.ini are modified
├── config.ini # global configurations
├── exps # exploit folders and scripts
├── manage.py # the main app to run submodules
├── requirements.txt
├── scripts # assists scripts
│   └── anastream.py # analyze tcp streams and extract exploit scripts
├── submit.json # define structure of flag submission
└── targets.json # configurations that are target/gamebox specific
```



## Tutorial

### Create exp

```shell
python manage.py create NAME
```

This command will create folders under `exps` according to `NAME` and create a template exploit under that folder. For example `python manage.py create ctf.pwn1` will create `ctf/pwn1` and `ctf/pwn1/exp.py` based on prelude/exp_template.py and initialize default configuration in `targets.json` and by default the configuration will be disabled. You can switch it on by set the `targets.json` or execute `python manage.py enable pwn1`.

I recommend always to create a exp with this command. If you don't use this command, you will need to create a folder under exps and add corresponding configuration in targets.json.


### Write exploits
You can write your exploits after you've created a namespace and properly set configurations in `targets.json`.
Notice that their must be a `pwn_remote` function which has host and port argument, and it returns flag and a "pwntools like" connection which help maintain the shell. Just like this:

```python
def pwn_remote(ip, port, *args, **kargs):
    '''pwn remote gamebox [ip]:[port], return flag and io'''
    io = remote(ip, port)
    flag = get_flag(io)
    if not kargs.get('keep_alive'):
        io.close()
    return flag, io
```

You can modify `prelude/exp_template.py` as you like so that you get a modified exp template next time you create a namespace. 
Currently the exploit are all loaded with environment python. But you can write a glue script to use `os.system` to utilize script written with different version of python.


### Run the framwork

```python
python manage.py run
```

You can also give a namespace scope to run


### Maintain shells

When the framework start, the shell manager service is also started. You can connect to the manager by the following command

```python
python manage.py sm
```
This command will spawn a cli client and connect to service whose host and port is configured in `config.ini`. Then you can cat flag, execute command and interact with shell. But the interactive shell is a simple hack one, and don't support some interactive command like vim, nano, etc.


### Write submitter

Usually we only need to change structure defined in `submit.json` to make the submitter works. If it can't meet your requirement, you can just modify the `Submitter.do_submit` function in `awdpwn/submit.py`. May be more usable submitter in competition will be integrated into the framework.


### Log

The awd logs will be saved to `awd.log`. Some statics analysis tools for log can be planned.


## Development guide

TODO
