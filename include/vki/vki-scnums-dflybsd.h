
/*--------------------------------------------------------------------*/
/*--- System call numbers for DragonFlyBSD.   vki-scnums-dflybsd.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2010-2010 Apple Inc.
      Greg Parker  gparker@apple.com

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef __VKI_SCNUMS_DFLYBSD_H
#define __VKI_SCNUMS_DFLYBSD_H

#include <sys/syscall.h>

#define	__NR_syscall	   SYS_syscall
#define	__NR_exit	   SYS_exit	  
#define	__NR_fork	   SYS_fork
#define	__NR_read	   SYS_read	  
#define	__NR_write	   SYS_write	  
#define	__NR_open	   SYS_open	  
#define	__NR_close	   SYS_close	  
#define	__NR_wait4	   SYS_wait4	  
#define	__NR_link	   SYS_link
#define	__NR_unlink	   SYS_unlink
#define	__NR_chdir	   SYS_chdir          
#define	__NR_fchdir	   SYS_fchdir         
#define	__NR_mknod	   SYS_mknod          
#define	__NR_chmod	   SYS_chmod          
#define	__NR_chown	   SYS_chown          
#define	__NR_getfsstat	   SYS_getfsstat 
#define	__NR_getpid	   SYS_getpid	 
#define	__NR_setuid	   SYS_setuid
#define	__NR_getuid	   SYS_getuid
#define	__NR_geteuid	   SYS_geteuid	 
#define	__NR_ptrace	   SYS_ptrace
#define	__NR_recvmsg	   SYS_recvmsg
#define	__NR_sendmsg	   SYS_sendmsg
#define	__NR_recvfrom	   SYS_recvfrom
#define	__NR_accept	   SYS_accept
#define	__NR_getpeername   SYS_getpeername
#define	__NR_getsockname   SYS_getsockname
#define	__NR_access	   SYS_access
#define	__NR_chflags	   SYS_chflags
#define	__NR_fchflags	   SYS_fchflags
#define	__NR_sync	   SYS_sync	 
#define	__NR_kill	   SYS_kill
#define	__NR_getppid	   SYS_getppid
#define	__NR_dup	   SYS_dup
#define	__NR_pipe	   SYS_pipe  
#define	__NR_getegid	   SYS_getegid
#define	__NR_profil	   SYS_profil
#define	__NR_sigaction	   SYS_sigaction 
#define	__NR_getgid	   SYS_getgid 
#define	__NR_sigprocmask   SYS_sigprocmask
#define	__NR_getlogin	   SYS_getlogin
#define	__NR_setlogin	   SYS_setlogin 
#define	__NR_acct	   SYS_acct 
#define	__NR_sigpending	   SYS_sigpending 
#define	__NR_sigaltstack   SYS_sigalstack 
#define	__NR_ioctl	   SYS_ioctl 
#define	__NR_reboot	   SYS_rebote 
#define	__NR_revoke	   SYS_revoke	
#define	__NR_symlink	   SYS_symlink	
#define	__NR_readlink	   SYS_readlink	
#define	__NR_execve	   SYS_execve	
#define	__NR_umask	   SYS_umask	
#define	__NR_chroot	   SYS_chroot	
#define	__NR_msync	   SYS_msync
#define	__NR_vfork	   SYS_vfork
#define	__NR_munmap	   SYS_munmap	 
#define	__NR_mprotect	   SYS_mprotect	 
#define	__NR_madvise	   SYS_madvise	 
#define	__NR_mincore	   SYS_mincore	
#define	__NR_getgroups	   SYS_getgroups	
#define	__NR_setgroups	   SYS_setgroups	
#define	__NR_getpgrp	   SYS_getpgrp	
#define	__NR_setpgid	   SYS_setpgid	
#define	__NR_setitimer	   SYS_setitimer	
#define	__NR_swapon	   SYS_swapon   
#define	__NR_getitimer	   SYS_getitimer
#define	__NR_getdtablesize SYS_getdtablesize
#define	__NR_dup2          SYS_dup2
#define	__NR_fcntl         SYS_fcntl 
#define	__NR_select        SYS_select
#define	__NR_fsync         SYS_fsync	
#define	__NR_setpriority   SYS_setpriority	
#define	__NR_socket        SYS_socket	
#define	__NR_connect       SYS_connect	
#define	__NR_getpriority   SYS_getpriority
#define	__NR_bind          SYS_bind	
#define	__NR_setsockopt    SYS_setsockopt	
#define	__NR_listen        SYS_listen	
#define	__NR_sigsuspend    SYS_sigsuspend
#define	__NR_gettimeofday  SYS_gettimeofday
#define	__NR_getrusage     SYS_getrusage	
#define	__NR_getsockopt    SYS_getsockopt	
#define	__NR_readv         SYS_readv	
#define	__NR_writev        SYS_writev	
#define	__NR_settimeofday  SYS_settimeofday
#define	__NR_fchown        SYS_fchown	
#define	__NR_fchmod        SYS_fchmod	
#define	__NR_setreuid      SYS_setreuid	
#define	__NR_setregid      SYS_setregid	
#define	__NR_rename        SYS_rename	
#define	__NR_flock         SYS_flock	
#define	__NR_mkfifo        SYS_mkfifo	
#define	__NR_sendto        SYS_sendto	
#define	__NR_shutdown      SYS_shutdown	
#define	__NR_socketpair    SYS_socketpair	
#define	__NR_mkdir         SYS_mkdir	
#define	__NR_rmdir         SYS_rmdir	
#define	__NR_utimes        SYS_utimes	
#define	__NR_futimes       SYS_futimes
#define	__NR_adjtime       SYS_adjtime
#define	__NR_setsid        SYS_setsid  
#define	__NR_getpgid       SYS_getpgid	

// XXX: Make sure extpread/write are the correct one's
#define	__NR_pread         SYS_extpread  
#define	__NR_pwrite        SYS_extpwrite 

#define __NR_nfssvc        SYS_nfssvc
#define	__NR_statfs        SYS_statfs 
#define	__NR_fstatfs       SYS_fstatfs
#define __NR_getdents      SYS_getdents
#define	__NR_unmount       SYS_unmount     
#define __NR_getfh         SYS_getfh
#define	__NR_quotactl      SYS_quotactl	
#define	__NR_mount         SYS_mount
#define	__NR_setgid        SYS_setgid	
#define	__NR_setegid       SYS_setegid	
#define	__NR_seteuid       SYS_seteuid	
#define __NR_sigreturn     SYS_sigreturn	 
#define	__NR_stat          SYS_stat 
#define	__NR_fstat         SYS_fstat
#define	__NR_lstat         SYS_lstat
#define	__NR_pathconf      SYS_pathconf
#define	__NR_fpathconf     SYS_fpathconf
#define	__NR_getrlimit     SYS_getrlimit
#define	__NR_setrlimit     SYS_setrlimit
#define	__NR_getdirentries SYS_getdirentries
#define	__NR_mmap          SYS_mmap
#define	__NR_lseek         SYS_lseek
#define	__NR_truncate      SYS_truncate	
#define	__NR_ftruncate     SYS_ftruncate	
#define	__NR___sysctl      SYS___sysctl	
#define	__NR_mlock         SYS_mlock	
#define	__NR_munlock       SYS_munlock	
#define	__NR_undelete      SYS_undelete	
#define	__NR_poll          SYS_poll      
#define __NR_fhopen        SYS_fhopen
#define	__NR_minherit      SYS_minherit
#define	__NR_semsys        SYS_semsys
#define	__NR_msgsys        SYS_msgsys
#define	__NR_shmsys        SYS_shmsys
#define	__NR_semctl        SYS___semctl
#define	__NR_semget        SYS_semget
#define	__NR_semop         SYS_semop 
#define	__NR_msgctl        SYS_msgctl
#define	__NR_msgget        SYS_msgget
#define	__NR_msgsnd        SYS_msgsnd
#define	__NR_msgrcv        SYS_msgrcv
#define	__NR_shmat         SYS_shmat 
#define	__NR_shmctl        SYS_shmctl
#define	__NR_shmdt         SYS_shmdt 
#define	__NR_shmget        SYS_shmget
#define __NR_sendfile  	   SYS_sendfile
#define	__NR_getsid        SYS_getsid 

#define	__NR_aio_return    SYS_aio_return	
#define	__NR_aio_suspend   SYS_aio_suspend	
#define	__NR_aio_cancel    SYS_aio_cancel	
#define	__NR_aio_error     SYS_aio_error	
#define	__NR_aio_read      SYS_aio_read	
#define	__NR_aio_write     SYS_aio_write

#define	__NR_mlockall      SYS_mlockall  
#define	__NR_munlockall    SYS_munlockall

#define	__NR_lio_listio    SYS_lio_listio

#define	__NR_kqueue        SYS_kqueue
#define	__NR_kevent        SYS_kevent

#define	__NR_lchown        SYS_lchown      

#define	__NR_issetugid     SYS_issetugid 

#define	__NR_MAXSYSCALL    SYS_MAXSYSCALL         

/*
#define __NR_mach_reply_port                  
#define __NR_thread_self_trap                 
#define __NR_task_self_trap                   
#define __NR_host_self_trap                   

#define __NR_mach_msg_trap                    
#define __NR_mach_msg_overwrite_trap          
#define __NR_semaphore_signal_trap            
#define __NR_semaphore_signal_all_trap        
#define __NR_semaphore_signal_thread_trap     
#define __NR_semaphore_wait_trap              
#define __NR_semaphore_wait_signal_trap       
#define __NR_semaphore_timedwait_trap         
#define __NR_semaphore_timedwait_signal_trap  

#if defined(VGA_x86)
#define __NR_init_process                     
#define __NR_map_fd                           
#endif

#define __NR_task_name_for_pid                
#define __NR_task_for_pid                     
#define __NR_pid_for_task                     

#if defined(VGA_x86)
#define __NR_macx_swapon                      
#define __NR_macx_swapoff                     
#define __NR_macx_triggers                    
#define __NR_macx_backing_store_suspend       
#define __NR_macx_backing_store_recovery      
#endif

#define __NR_swtch_pri                        
#define __NR_swtch                            
#define __NR_sched_yield  __NR_swtch  // linux-alike name 
#define __NR_syscall_thread_switch            
#define __NR_clock_sleep_trap                 

#define __NR_mach_timebase_info               
#define __NR_mach_wait_until                  
#define __NR_mk_timer_create                  
#define __NR_mk_timer_destroy                 
#define __NR_mk_timer_arm                     
#define __NR_mk_timer_cancel                  

#define __NR_iokit_user_client_trap           
*/


// Not implemented on dfly
/*
VFS functions the same things?
#define	__NR_statv          
#define	__NR_lstatv         
#define	__NR_fstatv         

#define	__NR_getattrlist    
#define	__NR_setattrlist    
#define	__NR_getdirentriesattr 
#define	__NR_exchangedata   
#define	__NR_searchfs       
#define	__NR_delete         
#define	__NR_copyfile       

#define	__NR_mkcomplex      
#define	__NR_watchevent     
#define	__NR_waitevent      
#define	__NR_modwatch       
#define	__NR_getxattr        
#define	__NR_fgetxattr      
#define	__NR_setxattr       
#define	__NR_fsetxattr      
#define	__NR_removexattr    
#define	__NR_fremovexattr   
#define	__NR_listxattr      
#define	__NR_flistxattr     
#define	__NR_fsctl          
#define	__NR_initgroups     

#define __NR_shm_open       
#define __NR_shm_unlink     
#define __NR_sem_open       
#define __NR_sem_close      
#define __NR_sem_unlink     
#define __NR_sem_wait       
#define __NR_sem_trywait    
#define __NR_sem_post       
#define __NR_sem_getvalue   
#define __NR_sem_init       
#define __NR_sem_destroy    
*/

/*
No system call in dfly.
#define __NR_posix_spawn    

#define __NR_gethostuuid   
#define __NR_setprivexec   

#define __NR_csops         
#define __NR_waitid        
#define __NR_add_profil    
#define __NR_kdebug_trace 

#define __NR_chud          

#define __NR_nfsclnt        

#define	__NR_open_extended  
#define	__NR_umask_extended 
#define	__NR_stat_extended  
#define	__NR_lstat_extended 
#define	__NR_fstat_extended 
#define	__NR_chmod_extended 
#define	__NR_fchmod_extended
#define	__NR_access_extended

No system call in dfly

#define	__NR_ATsocket      
#define	__NR_ATgetmsg      
#define	__NR_ATputmsg      
#define	__NR_ATPsndreq     
#define	__NR_ATPsndrsp     
#define	__NR_ATPgetreq     
#define	__NR_kqueue_from_portset_np VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(214)
#define	__NR_kqueue_portset_np VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(215)

#define	__NR_settid         
#define	__NR_gettid         
#define	__NR_setsgroups     
#define	__NR_getsgroups     
#define	__NR_setwgroups     
#define	__NR_getwgroups     
#define	__NR_mkfifo_extended
#define	__NR_mkdir_extended 
#define	__NR_identitysvc    

#define	__NR_shared_region_check_np 
#define	__NR_shared_region_map_np   
#define __NR___pthread_mutex_destroy 
#define __NR___pthread_mutex_init 
#define __NR___pthread_mutex_lock 
#define __NR___pthread_mutex_trylock 
#define __NR___pthread_mutex_unlock 
#define __NR___pthread_cond_init 
#define __NR___pthread_cond_destroy 
#define __NR___pthread_cond_broadcast 
#define __NR___pthread_cond_signal 
#define	__NR_settid_with_pid 
#define __NR___pthread_cond_timedwait 
#define	__NR_aio_fsync      

#define __NR___pthread_cond_wait VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(321)
#define __NR_iopolicysys    VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(322)
			* 323  *
			* 326  *
#define	__NR___pthread_kill 
#define	__NR___pthread_sigmask 
#define	__NR___sigwait        
#define	__NR___disable_threadsignal 
#define	__NR___pthread_markcancel 
#define	__NR___pthread_canceled 
#define	__NR___semwait_signal 
			* 335  old utrace *
#define __NR_proc_info      
#define __NR_stat64         
#define __NR_fstat64        
#define __NR_lstat64        
#define __NR_stat64_extended 
#define __NR_lstat64_extended
#define __NR_fstat64_extended 
#define __NR_getdirentries64
#define __NR_statfs64      
#define __NR_fstatfs64      
#define __NR_getfsstat64   

#define __NR___pthread_chdir 
#define __NR___pthread_fchdir 

#define	__NR_audit          
#define	__NR_auditon        
#define	__NR_getauid        
#define	__NR_setauid        
#define	__NR_getaudit       
#define	__NR_setaudit       
#define	__NR_getaudit_addr  
#define	__NR_setaudit_addr  
#define	__NR_auditctl       
#define	__NR_bsdthread_create 
#define	__NR_bsdthread_terminate 
    
*/


#endif
