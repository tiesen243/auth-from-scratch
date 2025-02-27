'use client'

import { useEffect, useState } from 'react'
import { MoonIcon, SunIcon } from 'lucide-react'
import { useTheme } from 'next-themes'

import { Button } from '@/components/ui/button'

export const ThemeBtn: React.FC = () => {
  const { theme, setTheme } = useTheme()

  const [isMounted, setIsMounted] = useState(false)
  useEffect(() => {
    setIsMounted(true)
  }, [])
  if (!isMounted)
    return (
      <Button
        size="icon"
        variant="outline"
        className="fixed right-4 bottom-4 animate-pulse"
        disabled
      />
    )

  return (
    <Button
      size="icon"
      variant="outline"
      className="fixed right-4 bottom-4"
      onClick={() => {
        setTheme(theme === 'dark' ? 'light' : 'dark')
      }}
    >
      {theme === 'dark' ? <MoonIcon /> : <SunIcon />}
    </Button>
  )
}
